package io.github.hectorvent.floci.services.accessanalyzer;

import com.fasterxml.jackson.core.JsonLocation;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.PaginatedResult;
import io.github.hectorvent.floci.core.common.Pagination;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.IntStream;

/** Stateless policy validation; findings never grant permissions or persist the submitted policy. */
@ApplicationScoped
public class PolicyValidationService {
    private static final Set<String> POLICY_TYPES = Set.of(
            "IDENTITY_POLICY", "RESOURCE_POLICY", "SERVICE_CONTROL_POLICY", "RESOURCE_CONTROL_POLICY");
    private static final Set<String> LOCALES = Set.of("DE", "EN", "ES", "FR", "IT", "JA", "KO", "PT_BR", "ZH_CN", "ZH_TW");
    private static final Set<String> RESOURCE_TYPES = Set.of("AWS::S3::Bucket", "AWS::S3::AccessPoint",
            "AWS::S3::MultiRegionAccessPoint", "AWS::S3ObjectLambda::AccessPoint",
            "AWS::IAM::AssumeRolePolicyDocument", "AWS::DynamoDB::Table");
    static final String CHECK_REFERENCE = "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
            + "access-analyzer-reference-policy-checks.html";
    private final ObjectMapper mapper;
    private static final Set<String> CONDITION_OPERATORS = Set.of("StringEquals", "StringNotEquals",
            "StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase", "StringLike", "StringNotLike",
            "NumericEquals", "NumericNotEquals", "NumericLessThan", "NumericLessThanEquals",
            "NumericGreaterThan", "NumericGreaterThanEquals", "DateEquals", "DateNotEquals",
            "DateLessThan", "DateLessThanEquals", "DateGreaterThan", "DateGreaterThanEquals",
            "Bool", "BinaryEquals", "IpAddress", "NotIpAddress", "ArnEquals", "ArnNotEquals", "ArnLike", "ArnNotLike", "Null");

    @Inject
    public PolicyValidationService(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public ObjectNode validate(JsonNode request, Integer maxResults, String nextToken) {
        String document = text(request, "policyDocument", true);
        String type = text(request, "policyType", true);
        if (!POLICY_TYPES.contains(type)) {
            throw invalid("policyType must identify a supported policy type.");
        }
        String locale = text(request, "locale", false);
        if (locale != null && !LOCALES.contains(locale)) {
            throw invalid("locale must identify a supported locale.");
        }
        String resourceType = text(request, "validatePolicyResourceType", false);
        if (resourceType != null && (!"RESOURCE_POLICY".equals(type) || !RESOURCE_TYPES.contains(resourceType))) {
            throw invalid("validatePolicyResourceType must identify a supported resource policy type.");
        }
        ObjectNode result = mapper.createObjectNode();
        result.putArray("findings");
        try {
            Document source = new Document(document);
            checkDocument(source, type, resourceType);
            source.findings.forEach(result.withArray("findings")::add);
        } catch (JsonProcessingException e) {
            JsonLocation location = e.getLocation();
            int offset = location == null ? 0 : (int) Math.clamp(location.getCharOffset(), 0, document.length());
            ObjectNode finding = mapper.createObjectNode().put("issueCode", "JSON_SYNTAX_ERROR")
                    .put("findingType", "ERROR").put("findingDetails", "Correct the policy document's JSON syntax.")
                    .put("learnMoreLink", CHECK_REFERENCE + "#access-analyzer-reference-policy-checks-error-json-syntax-error");
            ObjectNode source = finding.putArray("locations").addObject();
            source.putArray("path");
            ObjectNode span = source.putObject("span");
            span.set("start", position(document, offset));
            span.set("end", position(document, offset));
            result.withArray("findings").add(finding);
        } catch (IOException e) {
            throw new IllegalStateException("Could not read the policy document", e);
        }
        List<JsonNode> findings = new ArrayList<>();
        result.withArray("findings").forEach(findings::add);
        String namespace = "validate-policy:" + digest(document + "\u0000" + type + "\u0000"
                + (resourceType == null ? "" : resourceType) + "\u0000" + (locale == null ? "EN" : locale));
        PaginatedResult<Integer> page = Pagination.paginate(IntStream.range(0, findings.size()).boxed().toList(),
                index -> String.format(Locale.ROOT, "%010d", index), maxResults, nextToken,
                100, 1000, 2048, "ValidationException", namespace);
        ArrayNode items = result.putArray("findings");
        page.items().forEach(index -> items.add(findings.get(index)));
        if (page.nextToken() != null) {
            result.put("nextToken", page.nextToken());
        }
        return result;
    }

    private static String digest(String value) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    private void checkDocument(Document source, String type, String resourceType) {
        JsonNode root = source.root;
        if (!root.isObject()) {
            source.add("", "DATA_TYPE_MISMATCH", "ERROR", "The policy document must be an object.");
            return;
        }
        source.checkKeys(root, "", Set.of("Version", "Id", "Statement"));
        if (!root.has("Version")) {
            source.add("", "MISSING_VERSION", "WARNING", "Include a policy language Version for clarity.");
        } else if (!root.path("Version").isTextual()) {
            source.dataType("/Version", "a string");
        } else if (!Set.of("2012-10-17", "2008-10-17").contains(root.path("Version").asText())) {
            source.add("/Version", "INVALID_VERSION", "ERROR", "Use a supported policy language version.");
        }
        if (root.has("Id") && !root.path("Id").isTextual()) {
            source.dataType("/Id", "a string");
        }
        JsonNode statements = root.path("Statement");
        if (statements.isMissingNode() || statements.isNull() || statements.isArray() && statements.isEmpty()) {
            source.add("", "MISSING_STATEMENT", "ERROR", "The policy needs at least one statement.");
        } else if (statements.isObject()) {
            checkStatement(source, statements, "/Statement", type, resourceType, new HashSet<>());
        } else if (statements.isArray()) {
            Set<String> sids = new HashSet<>();
            for (int i = 0; i < statements.size(); i++) {
                checkStatement(source, statements.get(i), "/Statement/" + i, type, resourceType, sids);
            }
        } else {
            source.dataType("/Statement", "an object or an array of objects");
        }
    }

    private void checkStatement(Document source, JsonNode statement, String path, String type,
                                String resourceType, Set<String> sids) {
        if (!statement.isObject()) {
            source.dataType(path, "a statement object");
            return;
        }
        source.checkKeys(statement, path, Set.of("Sid", "Effect", "Principal", "NotPrincipal",
                "Action", "NotAction", "Resource", "NotResource", "Condition"));
        if (!statement.hasNonNull("Effect")) {
            source.add(path, "MISSING_EFFECT", "ERROR", "Specify the statement's Allow or Deny effect.");
        } else if (!statement.path("Effect").isTextual()) {
            source.dataType(path + "/Effect", "a string");
        } else if (!Set.of("Allow", "Deny").contains(statement.path("Effect").asText())) {
            source.add(path + "/Effect", "INVALID_EFFECT", "ERROR", "The effect must be Allow or Deny.");
        }
        checkPair(source, statement, path, "Action", "NotAction", true, "MISSING_ACTION");
        boolean trustPolicy = "AWS::IAM::AssumeRolePolicyDocument".equals(resourceType)
                || "RESOURCE_POLICY".equals(type) && hasAssumeRoleAction(statement.path("Action"));
        checkPair(source, statement, path, "Resource", "NotResource", !trustPolicy, "MISSING_RESOURCE");
        boolean resourcePolicy = "RESOURCE_POLICY".equals(type) || "RESOURCE_CONTROL_POLICY".equals(type);
        checkPair(source, statement, path, "Principal", "NotPrincipal", resourcePolicy, "MISSING_PRINCIPAL");
        for (String field : List.of("Action", "NotAction", "Resource", "NotResource")) {
            if (statement.has(field)) {
                checkStringList(source, statement.get(field), path + "/" + field,
                        field.endsWith("Action") ? "EMPTY_ARRAY_ACTION" : "EMPTY_ARRAY_RESOURCE");
            }
        }
        for (String field : List.of("Principal", "NotPrincipal")) {
            if (!statement.has(field)) {
                continue;
            }
            if (!resourcePolicy) {
                source.add(path + "/" + field,
                        "SERVICE_CONTROL_POLICY".equals(type) ? "SCP_SYNTAX_ERROR_PRINCIPAL" : "UNSUPPORTED_PRINCIPAL",
                        "ERROR", "This policy type does not accept a principal element.");
            } else {
                checkPrincipal(source, statement.get(field), path + "/" + field);
            }
        }
        if (statement.has("Sid")) {
            JsonNode sid = statement.get("Sid");
            if (!sid.isTextual()) {
                source.dataType(path + "/Sid", "a string");
            } else if (sid.asText().isEmpty()) {
                source.add(path + "/Sid", "EMPTY_SID_VALUE", "SUGGESTION", "Choose a nonempty statement identifier.");
            } else if (!sids.add(sid.asText())) {
                source.add(path + "/Sid", resourcePolicy ? "UNIQUE_SIDS_RECOMMENDED" : "UNIQUE_SIDS_REQUIRED",
                        resourcePolicy ? "WARNING" : "ERROR", "Use a different Sid for each statement.");
            }
        }
        if (statement.has("Condition")) {
            checkCondition(source, statement.get("Condition"), path + "/Condition");
        }
        if ("RESOURCE_CONTROL_POLICY".equals(type)) {
            checkResourceControlPolicy(source, statement, path);
        }
    }

    private static void checkResourceControlPolicy(Document source, JsonNode statement, String path) {
        if (statement.has("NotAction")) {
            source.add(path + "/NotAction", "RCP_SYNTAX_ERROR_NOTACTION", "ERROR", "Resource control policies require Action.");
        }
        if (statement.has("NotPrincipal") || statement.has("Principal") && !"*".equals(statement.path("Principal").asText())) {
            source.add(path, "RCP_SYNTAX_ERROR_PRINCIPAL", "ERROR", "Resource control policies require the wildcard principal.");
        }
        if ("Allow".equals(statement.path("Effect").asText()) && (statement.has("Condition")
                || !"*".equals(statement.path("Resource").asText()) || !"*".equals(statement.path("Principal").asText()))) {
            source.add(path, "RCP_SYNTAX_ERROR_ALLOW", "ERROR", "Allow statements in resource control policies require "
                    + "wildcard principals and resources without conditions.");
        }
    }

    private static boolean hasAssumeRoleAction(JsonNode actions) {
        if (actions.isTextual()) {
            return Set.of("sts:AssumeRole", "sts:AssumeRoleWithSAML", "sts:AssumeRoleWithWebIdentity")
                    .stream().anyMatch(action -> action.equalsIgnoreCase(actions.asText()));
        }
        if (actions.isArray()) {
            for (JsonNode action : actions) {
                if (hasAssumeRoleAction(action)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static void checkPair(Document source, JsonNode statement, String path, String first, String second,
                                  boolean required, String missingCode) {
        if (statement.has(first) && statement.has(second)) {
            source.add(path, "UNSUPPORTED_ELEMENT_COMBINATION", "ERROR", "Use either " + first + " or " + second + ".");
        } else if (required && !statement.hasNonNull(first) && !statement.hasNonNull(second)) {
            source.add(path, missingCode, "ERROR", "Include " + first + " or " + second + " in the statement.");
        }
    }

    private static void checkStringList(Document source, JsonNode node, String path, String emptyCode) {
        if (node.isTextual()) {
            return;
        }
        if (!node.isArray()) {
            source.dataType(path, "a string or an array of strings");
        } else if (node.isEmpty()) {
            source.add(path, emptyCode, "SUGGESTION", "Replace the empty array with the intended values.");
        } else {
            for (int i = 0; i < node.size(); i++) {
                if (!node.get(i).isTextual()) {
                    source.dataType(path + "/" + i, "a string");
                }
            }
        }
    }

    private static void checkPrincipal(Document source, JsonNode node, String path) {
        if (node.isTextual() && "*".equals(node.asText())) {
            return;
        }
        if (!node.isObject()) {
            source.add(path, "INVALID_PRINCIPAL_FORMAT", "ERROR", "Use a principal object or the wildcard principal.");
        } else if (node.isEmpty()) {
            source.add(path, "EMPTY_OBJECT_PRINCIPAL", "SUGGESTION", "Specify the intended principal.");
        } else {
            node.properties().forEach(entry -> checkStringList(source, entry.getValue(),
                    child(path, entry.getKey()), "EMPTY_ARRAY_PRINCIPAL"));
        }
    }

    private static void checkCondition(Document source, JsonNode node, String path) {
        if (!node.isObject()) {
            source.dataType(path, "an object");
        } else if (node.isEmpty()) {
            source.add(path, "EMPTY_OBJECT_CONDITION", "SUGGESTION", "Add the intended conditions or remove the empty object.");
        } else {
            node.properties().forEach(operator -> {
                String operatorPath = child(path, operator.getKey());
                if (!operator.getValue().isObject()) {
                    source.dataType(operatorPath, "a condition-key object");
                }
                String name = operator.getKey();
                if (name.startsWith("ForAllValues:") || name.startsWith("ForAnyValue:")) {
                    name = name.substring(name.indexOf(':') + 1);
                }
                if ("NullIfExists".equals(name)) {
                    source.add(operatorPath, "NULL_WITH_IF_EXISTS", "ERROR", "The Null operator cannot use IfExists.");
                } else {
                    String base = name.endsWith("IfExists") ? name.substring(0, name.length() - "IfExists".length()) : name;
                    if (!CONDITION_OPERATORS.contains(base)) {
                        source.add(operatorPath, "INVALID_CONDITION_OPERATOR", "ERROR", "Choose a supported condition operator.");
                    }
                }
            });
        }
    }

    private record Span(List<Object> path, int start, int end) {}

    /** Keeps the original source ranges while parsing, rather than locating reformatted JSON. */
    private final class Document {
        private final String text;
        private final JsonNode root;
        private final Map<String, Span> spans = new LinkedHashMap<>();
        private final List<ObjectNode> findings = new ArrayList<>();

        private Document(String text) throws IOException {
            this.text = text;
            try (JsonParser parser = mapper.getFactory().createParser(text)) {
                if (parser.nextToken() == null) {
                    throw new JsonParseException(parser, "The policy is empty.");
                }
                root = read(parser, "", List.of());
                if (parser.nextToken() != null) {
                    throw new JsonParseException(parser, "The policy has trailing JSON.");
                }
            }
        }

        private JsonNode read(JsonParser parser, String pointer, List<Object> path) throws IOException {
            int start = (int) parser.currentTokenLocation().getCharOffset();
            JsonToken token = parser.currentToken();
            JsonNode node;
            if (token == JsonToken.START_OBJECT) {
                ObjectNode object = mapper.createObjectNode();
                while (parser.nextToken() != JsonToken.END_OBJECT) {
                    String field = parser.currentName();
                    parser.nextToken();
                    object.set(field, read(parser, child(pointer, field), append(path, field)));
                }
                node = object;
            } else if (token == JsonToken.START_ARRAY) {
                ArrayNode array = mapper.createArrayNode();
                while (parser.nextToken() != JsonToken.END_ARRAY) {
                    int index = array.size();
                    array.add(read(parser, pointer + "/" + index, append(path, index)));
                }
                node = array;
            } else if (token == JsonToken.VALUE_STRING) {
                node = mapper.getNodeFactory().textNode(parser.getText());
            } else if (token == JsonToken.VALUE_NUMBER_INT) {
                node = mapper.getNodeFactory().numberNode(parser.getBigIntegerValue());
            } else if (token == JsonToken.VALUE_NUMBER_FLOAT) {
                node = mapper.getNodeFactory().numberNode(parser.getDecimalValue());
            } else if (token == JsonToken.VALUE_TRUE || token == JsonToken.VALUE_FALSE) {
                node = mapper.getNodeFactory().booleanNode(token == JsonToken.VALUE_TRUE);
            } else if (token == JsonToken.VALUE_NULL) {
                node = mapper.getNodeFactory().nullNode();
            } else {
                throw new JsonParseException(parser, "Unexpected policy token.");
            }
            spans.put(pointer, new Span(path, start, (int) parser.currentLocation().getCharOffset()));
            return node;
        }

        private void checkKeys(JsonNode node, String path, Set<String> allowed) {
            node.fieldNames().forEachRemaining(key -> {
                if (!allowed.contains(key)) {
                    add(child(path, key), "INVALID_POLICY_ELEMENT", "ERROR", "Remove the unsupported policy element " + key + ".");
                }
            });
        }

        private void dataType(String path, String expected) {
            add(path, "DATA_TYPE_MISMATCH", "ERROR", "This policy value must be " + expected + ".");
        }

        private void add(String pointer, String code, String type, String details) {
            Span span = spans.getOrDefault(pointer, spans.get(""));
            ObjectNode finding = mapper.createObjectNode().put("issueCode", code).put("findingType", type)
                    .put("findingDetails", details).put("learnMoreLink", CHECK_REFERENCE);
            ObjectNode location = finding.putArray("locations").addObject();
            for (Object element : span.path()) {
                ObjectNode member = location.withArray("path").addObject();
                if (element instanceof Integer index) {
                    member.put("index", index);
                } else {
                    member.put("value", element.toString());
                }
            }
            if (span.path().isEmpty()) {
                location.putArray("path");
            }
            ObjectNode range = location.putObject("span");
            range.set("start", position(text, span.start()));
            range.set("end", position(text, span.end()));
            findings.add(finding);
        }
    }

    private static String child(String path, String key) {
        return path + "/" + key.replace("~", "~0").replace("/", "~1");
    }

    private static List<Object> append(List<Object> path, Object element) {
        List<Object> result = new ArrayList<>(path);
        result.add(element);
        return List.copyOf(result);
    }

    private ObjectNode position(String document, int offset) {
        int line = 1;
        int column = 0;
        for (int i = 0; i < offset; i++) {
            if (document.charAt(i) == '\r') {
                line++;
                column = 0;
                if (i + 1 < offset && document.charAt(i + 1) == '\n') {
                    i++;
                }
            } else if (document.charAt(i) == '\n') {
                line++;
                column = 0;
            } else {
                column++;
            }
        }
        return mapper.createObjectNode().put("offset", offset).put("line", line).put("column", column);
    }

    private static String text(JsonNode request, String key, boolean required) {
        if (request == null || !request.isObject()) {
            throw invalid("The request must be a JSON object.");
        }
        JsonNode value = request.get(key);
        if (value == null || value.isNull()) {
            if (required) {
                throw invalid(key + " is required.");
            }
            return null;
        }
        if (!value.isTextual()) {
            throw invalid(key + " must be a string.");
        }
        return value.textValue();
    }

    private static AwsException invalid(String message) {
        return new AwsException("ValidationException", message, 400);
    }
}
