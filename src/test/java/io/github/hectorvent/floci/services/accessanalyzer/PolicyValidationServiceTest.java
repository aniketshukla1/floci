package io.github.hectorvent.floci.services.accessanalyzer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.util.stream.StreamSupport;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PolicyValidationServiceTest {
    private final ObjectMapper mapper = new ObjectMapper();
    private final PolicyValidationService service = new PolicyValidationService(mapper);

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "{}|MISSING_STATEMENT",
        "[]|DATA_TYPE_MISMATCH",
        "{\"Statement\":[]}|MISSING_STATEMENT",
        "{\"Statement\":{}}|MISSING_EFFECT",
        "{\"Statement\":{\"Effect\":\"Permit\"}}|INVALID_EFFECT",
        "{\"Statement\":{\"Effect\":true}}|DATA_TYPE_MISMATCH",
        "{\"Statement\":{\"Effect\":\"Allow\"}}|MISSING_ACTION",
        "{\"Statement\":{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\"}}|MISSING_RESOURCE",
        "{\"Statement\":{\"Effect\":\"Allow\",\"Action\":[],\"Resource\":\"*\"}}|EMPTY_ARRAY_ACTION",
        "{\"Statement\":{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":[]}}|EMPTY_ARRAY_RESOURCE",
        "{\"Statement\":{\"Action\":true}}|DATA_TYPE_MISMATCH",
        "{\"Statement\":{\"Action\":\"s3:GetObject\",\"NotAction\":\"s3:PutObject\"}}|UNSUPPORTED_ELEMENT_COMBINATION",
        "{\"Statement\":{\"Principal\":\"*\"}}|UNSUPPORTED_PRINCIPAL",
        "{\"Statement\":{\"Other\":true}}|INVALID_POLICY_ELEMENT",
        "{\"Statement\":{\"Sid\":\"\"}}|EMPTY_SID_VALUE",
        "{\"Version\":\"2020-01-01\",\"Statement\":{}}|INVALID_VERSION",
        "{\"Statement\":{\"Condition\":[]}}|DATA_TYPE_MISMATCH"
    })
    void reportsDocumentAndStatementGrammarFindings(String policy, String code) {
        JsonNode result = validate(policy);
        assertTrue(StreamSupport.stream(result.path("findings").spliterator(), false)
                .anyMatch(finding -> code.equals(finding.path("issueCode").asText())), result::toString);
    }

    @Test
    void findingSpanPointsToTheSubmittedValueAndUsesAnArrayPath() {
        String policy = """
                {
                  "Version": "2012-10-17",
                  "Statement": [{
                    "Effect": "Permit",
                    "Action": "s3:GetObject", "Resource": "*"
                  }]
                }
                """;
        JsonNode finding = StreamSupport.stream(validate(policy).path("findings").spliterator(), false)
                .filter(item -> "INVALID_EFFECT".equals(item.path("issueCode").asText())).findFirst().orElseThrow();
        JsonNode location = finding.path("locations").get(0);
        int start = policy.indexOf("\"Permit\"");
        assertEquals(start, location.at("/span/start/offset").asInt());
        assertEquals(start + 8, location.at("/span/end/offset").asInt());
        assertEquals(4, location.at("/span/start/line").asInt());
        assertEquals("Statement", location.at("/path/0/value").asText());
        assertEquals(0, location.at("/path/1/index").asInt());
        assertEquals("Effect", location.at("/path/2/value").asText());
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "RESOURCE_POLICY|{\"Statement\":{\"Effect\":\"Allow\",\"Action\":\"s3:GetObject\",\"Resource\":\"*\"}}|MISSING_PRINCIPAL",
        "SERVICE_CONTROL_POLICY|{\"Statement\":{\"Principal\":\"*\"}}|SCP_SYNTAX_ERROR_PRINCIPAL",
        "RESOURCE_CONTROL_POLICY|{\"Statement\":{\"NotAction\":\"s3:GetObject\"}}|RCP_SYNTAX_ERROR_NOTACTION",
        "RESOURCE_CONTROL_POLICY|{\"Statement\":{\"Principal\":{\"AWS\":\"123456789012\"}}}|RCP_SYNTAX_ERROR_PRINCIPAL",
        "RESOURCE_CONTROL_POLICY|{\"Statement\":{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Resource\":\"*\",\"Condition\":{}}}|RCP_SYNTAX_ERROR_ALLOW",
        "IDENTITY_POLICY|{\"Statement\":{\"Condition\":{\"UnknownOperator\":{\"aws:username\":\"user\"}}}}|INVALID_CONDITION_OPERATOR"
    })
    void reportsPolicyTypeAndConditionGrammar(String type, String policy, String code) {
        JsonNode result = service.validate(mapper.createObjectNode().put("policyType", type).put("policyDocument", policy), null, null);
        assertTrue(StreamSupport.stream(result.path("findings").spliterator(), false)
                .anyMatch(finding -> code.equals(finding.path("issueCode").asText())), result::toString);
    }

    @Test
    void sourcePositionsCountCarriageReturnLineBreaks() {
        String policy = "{\r\"Version\":\"2012-10-17\",\r\"Statement\":{\"Effect\":\"Permit\"}}";
        JsonNode finding = StreamSupport.stream(validate(policy).path("findings").spliterator(), false)
                .filter(item -> "INVALID_EFFECT".equals(item.path("issueCode").asText())).findFirst().orElseThrow();
        assertEquals(3, finding.at("/locations/0/span/start/line").asInt());
    }

    private ObjectNode validate(String policy) {
        ObjectNode request = mapper.createObjectNode().put("policyDocument", policy).put("policyType", "IDENTITY_POLICY");
        return service.validate(request, null, null);
    }
}
