package io.github.hectorvent.floci.services.route53;

import io.github.hectorvent.floci.testing.AwsTestClients;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.route53.Route53Client;
import software.amazon.awssdk.services.route53.model.DelegationSet;
import software.amazon.awssdk.services.route53.model.ListReusableDelegationSetsResponse;
import software.amazon.awssdk.services.route53.model.Route53Exception;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
class Route53DelegationSetsIntegrationTest {
    @Test
    void createGetAndDeleteRoundTripThroughAwsSdk() {
        try (Route53Client client = client("741686000001", Region.US_EAST_1)) {
            String reference = "delegation<&>" + UUID.randomUUID();
            DelegationSet created = client.createReusableDelegationSet(r -> r.callerReference(reference)).delegationSet();
            try {
                assertTrue(created.id().startsWith("N"));
                assertEquals(reference, created.callerReference());
                assertEquals(4, created.nameServers().size());
                assertEquals(created, client.getReusableDelegationSet(r -> r.id(created.id())).delegationSet());
            } finally {
                client.deleteReusableDelegationSet(r -> r.id(created.id()));
            }
            assertError("NoSuchDelegationSet", () -> client.getReusableDelegationSet(r -> r.id(created.id())));
        }
    }

    @Test
    void duplicateCallerReferenceIsRejectedWithoutCreatingAnotherSet() {
        try (Route53Client client = client("741686000002", Region.US_EAST_1)) {
            String reference = UUID.randomUUID().toString();
            String id = client.createReusableDelegationSet(r -> r.callerReference(reference)).delegationSet().id();
            try {
                assertError("DelegationSetAlreadyCreated", () ->
                        client.createReusableDelegationSet(r -> r.callerReference(reference)));
                assertEquals(1, client.listReusableDelegationSets().delegationSets().size());
            } finally {
                client.deleteReusableDelegationSet(r -> r.id(id));
            }
        }
    }

    @Test
    void listIncludesEverySetOnceUsingFirstUnseenId() {
        try (Route53Client client = client("741686000003", Region.US_EAST_1)) {
            List<String> ids = new ArrayList<>();
            try {
                for (int i = 0; i < 3; i++) {
                    ids.add(client.createReusableDelegationSet(r -> r.callerReference(UUID.randomUUID().toString()))
                            .delegationSet().id());
                }
                List<ListReusableDelegationSetsResponse> pages = new ArrayList<>();
                String marker = null;
                do {
                    String next = marker;
                    ListReusableDelegationSetsResponse page = client.listReusableDelegationSets(r ->
                            r.maxItems("1").marker(next));
                    pages.add(page);
                    marker = page.nextMarker();
                } while (pages.getLast().isTruncated() && pages.size() < 4);
                assertEquals(3, pages.size());
                assertEquals(ids.stream().sorted().toList(), pages.stream()
                        .flatMap(p -> p.delegationSets().stream()).map(DelegationSet::id).toList());
                assertTrue(pages.getFirst().isTruncated());
                assertEquals(pages.get(1).delegationSets().getFirst().id().replace("/delegationset/", ""),
                        pages.getFirst().nextMarker());
                assertFalse(pages.getLast().isTruncated());
                assertEquals(null, pages.getLast().nextMarker());
            } finally {
                ids.forEach(id -> client.deleteReusableDelegationSet(r -> r.id(id)));
            }
        }
    }

    @Test
    void setsAreAccountScopedAndGlobalAcrossRegions() {
        try (Route53Client owner = client("741686000004", Region.US_EAST_1);
             Route53Client otherRegion = client("741686000004", Region.EU_WEST_1);
             Route53Client stranger = client("741686000005", Region.US_EAST_1)) {
            String reference = UUID.randomUUID().toString();
            DelegationSet set = owner.createReusableDelegationSet(r -> r.callerReference(reference)).delegationSet();
            try {
                assertEquals(set, otherRegion.getReusableDelegationSet(r -> r.id(set.id())).delegationSet());
                assertTrue(stranger.listReusableDelegationSets().delegationSets().isEmpty());
                assertError("NoSuchDelegationSet", () -> stranger.getReusableDelegationSet(r -> r.id(set.id())));
                assertError("NoSuchDelegationSet", () -> stranger.deleteReusableDelegationSet(r -> r.id(set.id())));
                String foreignId = stranger.createReusableDelegationSet(r -> r.callerReference(reference))
                        .delegationSet().id();
                stranger.deleteReusableDelegationSet(r -> r.id(foreignId));
            } finally {
                owner.deleteReusableDelegationSet(r -> r.id(set.id()));
            }
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 129})
    void callerReferenceLengthIsValidated(int length) {
        try (Route53Client client = client("741686000006", Region.US_EAST_1)) {
            assertError("InvalidInput", () -> client.createReusableDelegationSet(r -> r.callerReference("x".repeat(length))));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"0", "-1", "no"})
    void invalidPageSizeHasAnAwsXmlError(String size) {
        given().queryParam("maxitems", size).when().get("/2013-04-01/delegationset")
                .then().statusCode(400).body(containsString("<Code>InvalidInput</Code>"));
    }

    @Test
    void positivePageSizeBeyondIntegerRangeIsAccepted() {
        try (Route53Client client = client("741686000007", Region.US_EAST_1)) {
            ListReusableDelegationSetsResponse page = client.listReusableDelegationSets(r -> r.maxItems("2147483648"));
            assertEquals("2147483648", page.maxItems());
            assertFalse(page.isTruncated());
        }
    }

    private Route53Client client(String account, Region region) {
        return AwsTestClients.create(Route53Client.builder(), account, region);
    }

    private void assertError(String code, Runnable action) {
        Route53Exception error = assertThrows(Route53Exception.class, action::run);
        assertEquals(400, error.statusCode());
        assertEquals(code, error.awsErrorDetails().errorCode());
    }
}
