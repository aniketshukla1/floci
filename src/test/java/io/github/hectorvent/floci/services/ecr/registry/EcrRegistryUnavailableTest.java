package io.github.hectorvent.floci.services.ecr.registry;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.services.ecr.EcrService;
import io.github.hectorvent.floci.testutil.FreePorts;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpClient;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.RequestOptions;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class EcrRegistryUnavailableTest {

    private Vertx vertx;
    private HttpServer server;
    private HttpClient client;
    private EcrRegistryManager manager;

    @BeforeEach
    void startDataPlane() throws Exception {
        vertx = Vertx.vertx();
        client = vertx.createHttpClient();
        manager = mock(EcrRegistryManager.class);
        EmulatorConfig config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
        when(config.services().ecr().enabled()).thenReturn(true);
        when(config.services().ecr().uriStyle()).thenReturn("hostname");
        EcrService service = mock(EcrService.class);
        when(service.registryRepositoryName("example", "000000000000", "us-east-1"))
                .thenReturn("000000000000/us-east-1/example");
        Router router = Router.router(vertx);
        new EcrRegistryDataPlane(manager, service, config, vertx).register(router);
        server = vertx.createHttpServer().requestHandler(router).listen(0, "127.0.0.1")
                .toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
        when(manager.httpClient()).thenReturn(new RegistryHttpClient(
                "http://127.0.0.1:" + FreePorts.loopbackIpv4Port()));
    }

    @AfterEach
    void stopDataPlane() throws Exception {
        vertx.close().toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
    }

    @ParameterizedTest
    @CsvSource({"true,GET,/v2/", "false,GET,/v2/",
            "true,PUT,/v2/example/manifests/latest", "false,PUT,/v2/example/manifests/latest"})
    void unavailableRegistryExplainsTheNetworkRequirement(boolean startupFailure, String method, String path)
            throws Exception {
        failStartupIfRequested(startupFailure);
        RegistryResponse response = request(HttpMethod.valueOf(method), path);
        assertEquals(503, response.status());
        assertEquals("application/json", response.contentType());
        assertEquals("registry/2.0", response.apiVersion());
        assertFalse(response.body().isBlank());
        JsonArray errors = new JsonObject(response.body()).getJsonArray("errors");
        assertNotNull(errors);
        assertEquals(1, errors.size());
        JsonObject error = errors.getJsonObject(0);
        assertEquals("UNAVAILABLE", error.getString("code"));
        String message = error.getString("message");
        assertTrue(message.contains("registry"));
        assertTrue(message.contains("user-defined network"));
        assertTrue(message.contains("FLOCI_SERVICES_ECR_DOCKER_NETWORK"));
        assertFalse(response.body().contains("internal-startup-detail"));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void headFailuresKeepRegistryHeadersWithoutSendingABody(boolean startupFailure) throws Exception {
        failStartupIfRequested(startupFailure);
        RegistryResponse response = request(HttpMethod.HEAD, "/v2/example/manifests/latest");
        assertEquals(503, response.status());
        assertEquals("application/json", response.contentType());
        assertEquals("registry/2.0", response.apiVersion());
        assertTrue(response.body().isEmpty());
    }

    @Test
    void upstreamErrorResponsesPassThroughUnchanged() throws Exception {
        HttpServer registry = vertx.createHttpServer().requestHandler(request -> request.response()
                        .setStatusCode(503).putHeader("Content-Type", "text/plain").end("registry temporarily busy"))
                .listen(0, "127.0.0.1").toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
        when(manager.httpClient()).thenReturn(new RegistryHttpClient("http://127.0.0.1:" + registry.actualPort()));
        RegistryResponse response = request(HttpMethod.GET, "/v2/");
        assertEquals(503, response.status());
        assertEquals("text/plain", response.contentType());
        assertEquals("registry temporarily busy", response.body());
        assertNull(response.apiVersion());
    }

    private void failStartupIfRequested(boolean startupFailure) {
        if (startupFailure) {
            doThrow(new IllegalStateException("internal-startup-detail")).when(manager).ensureStarted();
        }
    }

    private RegistryResponse request(HttpMethod method, String path) throws Exception {
        return client.request(new RequestOptions().setHost("127.0.0.1").setPort(server.actualPort())
                        .setMethod(method).setURI(path))
                .compose(request -> request.putHeader("Host", "000000000000.dkr.ecr.us-east-1.localhost:4566").send())
                .compose(response -> response.body().map(body -> new RegistryResponse(response.statusCode(),
                        response.getHeader("Content-Type"), response.getHeader("Docker-Distribution-API-Version"),
                        body.toString())))
                .toCompletionStage().toCompletableFuture().get(5, TimeUnit.SECONDS);
    }

    private record RegistryResponse(int status, String contentType, String apiVersion, String body) {}
}
