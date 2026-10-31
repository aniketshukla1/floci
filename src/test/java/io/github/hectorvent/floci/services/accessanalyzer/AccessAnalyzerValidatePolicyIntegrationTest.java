package io.github.hectorvent.floci.services.accessanalyzer;

import io.github.hectorvent.floci.testing.AwsTestClients;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.accessanalyzer.AccessAnalyzerClient;
import software.amazon.awssdk.services.accessanalyzer.model.PolicyType;
import software.amazon.awssdk.services.accessanalyzer.model.ValidatePolicyResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
class AccessAnalyzerValidatePolicyIntegrationTest {

    @Test
    void validIdentityPolicyNeedsNoAnalyzerAndHasNoFindings() {
        try (AccessAnalyzerClient client = AwsTestClients.create(
                AccessAnalyzerClient.builder(), "test", Region.US_EAST_1)) {
            ValidatePolicyResponse result = client.validatePolicy(r -> r.policyType(PolicyType.IDENTITY_POLICY)
                    .policyDocument("""
                            {"Version":"2012-10-17","Statement":[{
                              "Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}
                            """));

            assertTrue(result.findings().isEmpty());
        }
    }

    @Test
    void malformedPolicyJsonReturnsAnErrorFindingThroughTheSdk() {
        try (AccessAnalyzerClient client = AwsTestClients.create(
                AccessAnalyzerClient.builder(), "test", Region.US_EAST_1)) {
            ValidatePolicyResponse result = client.validatePolicy(r -> r.policyType(PolicyType.IDENTITY_POLICY)
                    .policyDocument("{\n  \"Statement\": [}"));

            assertEquals("JSON_SYNTAX_ERROR", result.findings().getFirst().issueCode());
            assertEquals("ERROR", result.findings().getFirst().findingTypeAsString());
            assertEquals(2, result.findings().getFirst().locations().getFirst().span().start().line());
        }
    }

    @Test
    void findingsPaginateThroughTheSdk() {
        try (AccessAnalyzerClient client = AwsTestClients.create(
                AccessAnalyzerClient.builder(), "test", Region.US_EAST_1)) {
            ValidatePolicyResponse first = client.validatePolicy(r -> r.policyType(PolicyType.IDENTITY_POLICY)
                    .policyDocument("{}").maxResults(1));
            assertEquals(1, first.findings().size());
            assertNotNull(first.nextToken());
            ValidatePolicyResponse second = client.validatePolicy(r -> r.policyType(PolicyType.IDENTITY_POLICY)
                    .policyDocument("{}").maxResults(1).nextToken(first.nextToken()));
            assertEquals(1, second.findings().size());
            assertTrue(!first.findings().getFirst().issueCode().equals(second.findings().getFirst().issueCode()));
        }
    }
}
