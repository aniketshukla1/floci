package io.github.hectorvent.floci.services.cloudformation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.services.apigatewayv2.ApiGatewayV2Service;
import io.github.hectorvent.floci.services.apigatewayv2.model.Api;
import io.github.hectorvent.floci.services.apigatewayv2.model.Route;
import io.github.hectorvent.floci.services.cloudformation.model.StackResource;
import io.github.hectorvent.floci.services.cloudformation.provisioners.CloudFormationResourceRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ApiGatewayV2CfnProvisionerTest {

    private static final String REGION = "us-east-1";
    private static final String API_ID = "api-123";
    private final ObjectMapper mapper = new ObjectMapper();
    private ApiGatewayV2Service apiGatewayV2Service;
    private CloudFormationResourceProvisioner provisioner;

    @BeforeEach
    void setUp() {
        apiGatewayV2Service = mock(ApiGatewayV2Service.class);
        provisioner = new CloudFormationResourceProvisioner(
                null, null, null, null, null, null, null, null, null, null,
                null, apiGatewayV2Service, null, null, null, null, mapper,
                null, null, null, null, null, null, null, null, null, null,
                null, null, null, null, new CloudFormationResourceRegistry(java.util.List.of()));

        Api api = new Api();
        api.setApiId(API_ID);
        api.setApiEndpoint("https://" + API_ID + ".execute-api.localhost");
        when(apiGatewayV2Service.createApi(eq(REGION), anyMap())).thenReturn(api);
        when(apiGatewayV2Service.updateApi(eq(REGION), eq(API_ID), anyMap())).thenReturn(api);
    }

    @Test
    void keepsExistingRoutesAndCleansPartialReplacementWhenRouteCreationFails() throws Exception {
        when(apiGatewayV2Service.createRoute(eq(REGION), eq(API_ID), anyMap())).thenAnswer(invocation -> {
            @SuppressWarnings("unchecked")
            Map<String, Object> request = invocation.getArgument(2);
            return switch ((String) request.get("routeKey")) {
                case "GET /before" -> route("old-route", "GET /before");
                case "GET /first" -> route("partial-route", "GET /first");
                case "GET /second" -> throw new AwsException("InternalFailure", "simulated route failure", 500);
                default -> throw new AssertionError("Unexpected route key: " + request.get("routeKey"));
            };
        });

        StackResource original = provision(body("""
                {"paths":{"/before":{"get":{}}}}
                """), null, Map.of());

        StackResource replacement = provision(body("""
                {"paths":{"/first":{"get":{}},"/second":{"get":{}}}}
                """), original.getPhysicalId(), original.getAttributes());

        assertEquals("CREATE_COMPLETE", original.getStatus());
        assertEquals("CREATE_FAILED", replacement.getStatus());
        assertEquals("old-route", replacement.getAttributes().get("__FlociApiGatewayV2BodyRouteIds"));
        verify(apiGatewayV2Service, never()).deleteRoute(REGION, API_ID, "old-route");
        verify(apiGatewayV2Service).deleteRoute(REGION, API_ID, "partial-route");
    }

    private StackResource provision(JsonNode properties, String existingPhysicalId,
                                    Map<String, String> existingAttributes) {
        return provisioner.provision("HttpApi", "AWS::ApiGatewayV2::Api", properties, engine(), REGION,
                "000000000000", "test-stack", existingPhysicalId, existingAttributes);
    }

    private JsonNode body(String body) throws Exception {
        return mapper.readTree("""
                {"Name":"test-api","ProtocolType":"HTTP","Body":%s}
                """.formatted(body));
    }

    private CloudFormationTemplateEngine engine() {
        return new CloudFormationTemplateEngine("000000000000", REGION, "test-stack", "stack/id",
                Map.of(), Map.of(), Map.of(), Map.of(), Map.of(), mapper,
                (Function<String, String>) name -> null);
    }

    private static Route route(String id, String routeKey) {
        Route route = new Route();
        route.setRouteId(id);
        route.setRouteKey(routeKey);
        return route;
    }
}
