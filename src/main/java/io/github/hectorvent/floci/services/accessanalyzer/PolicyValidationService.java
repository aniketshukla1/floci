package io.github.hectorvent.floci.services.accessanalyzer;

import com.fasterxml.jackson.core.JsonLocation;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.core.common.AwsException;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.Set;

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

    @Inject
    public PolicyValidationService(ObjectMapper mapper) {
        this.mapper = mapper;
    }

    public ObjectNode validate(JsonNode request) {
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
            mapper.reader().with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).readTree(document);
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
        }
        return result;
    }

    private ObjectNode position(String document, int offset) {
        int line = 1;
        int column = 0;
        for (int i = 0; i < offset; i++) {
            if (document.charAt(i) == '\n') {
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
