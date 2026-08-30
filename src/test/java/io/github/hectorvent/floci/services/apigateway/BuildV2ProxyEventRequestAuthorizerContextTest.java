package io.github.hectorvent.floci.services.apigateway;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.RegionResolver;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Verifies that an HTTP API Lambda REQUEST authorizer's response context is forwarded to the
 * integration event at {@code requestContext.authorizer.lambda}.
 */
class BuildV2ProxyEventRequestAuthorizerContextTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ApiGatewayExecuteController controller;
    private HttpHeaders headers;
    private UriInfo uriInfo;

    @BeforeEach
    void setUp() throws Exception {
        RegionResolver regionResolver = mock(RegionResolver.class);
        when(regionResolver.getAccountId()).thenReturn("000000000000");

        headers = mock(HttpHeaders.class);
        when(headers.getRequestHeaders()).thenReturn(new MultivaluedHashMap<>());
        when(headers.getHeaderString("User-Agent")).thenReturn(null);

        uriInfo = mock(UriInfo.class);
        when(uriInfo.getQueryParameters()).thenReturn(new MultivaluedHashMap<>());
        when(uriInfo.getRequestUri()).thenReturn(new URI("http://localhost:4566/api/stage/hello"));

        controller = new ApiGatewayExecuteController(
                null, null, null,
                regionResolver, MAPPER, null,
                null, null, null, null, new ApiGatewayExecuteRouteContext(), null, null
        );
    }

    @Test
    void forwardsRequestAuthorizerContextUnderLambda() throws Exception {
        JsonNode authorizerContext = MAPPER.readTree("""
                {
                  "userId": "user123",
                  "role": "admin",
                  "limits": {"requests": 25}
                }
                """);

        String json = controller.buildV2ProxyEvent(
                "GET", "/hello", "GET /hello",
                "abc123", "us-east-1", "stage", headers, uriInfo, null, "req-1",
                null, null, authorizerContext);
        JsonNode event = MAPPER.readTree(json);

        assertEquals(authorizerContext, event.at("/requestContext/authorizer/lambda"));
    }

    @Test
    void omitsAuthorizerWhenNoContextWasReturned() throws Exception {
        String json = controller.buildV2ProxyEvent(
                "GET", "/hello", "GET /hello",
                "abc123", "us-east-1", "stage", headers, uriInfo, null, "req-2",
                null, null, null);
        JsonNode event = MAPPER.readTree(json);

        assertFalse(event.at("/requestContext").has("authorizer"));
    }
}
