package io.github.hectorvent.floci.services.lambda.launcher;

import com.github.dockerjava.api.model.AccessMode;
import com.github.dockerjava.api.model.Bind;
import io.github.hectorvent.floci.core.common.docker.ContainerBuilder;
import io.github.hectorvent.floci.core.common.docker.ContainerSpec;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LambdaDockerFlagsTest {

    @Test
    void appliesSupportedFlagsToTheLambdaContainerSpec() {
        ContainerBuilder.Builder builder = builder();

        LambdaDockerFlags.apply(builder, """
                -e NODE_EXTRA_CA_CERTS='/certs/root ca.pem'
                --volume '/host certs:/certs:ro'
                --publish 127.0.0.1:9229:9229/tcp
                --add-host=internal.test:host-gateway
                --network lambda-net
                --user 1001:1001
                --dns 1.1.1.1
                --privileged
                """);

        ContainerSpec spec = builder.build();
        assertTrue(spec.env().contains("NODE_EXTRA_CA_CERTS=/certs/root ca.pem"));
        assertEquals(1, spec.binds().size());
        Bind bind = spec.binds().getFirst();
        assertEquals("/host certs", bind.getPath());
        assertEquals("/certs", bind.getVolume().getPath());
        assertEquals(AccessMode.ro, bind.getAccessMode());
        assertEquals(9229, spec.portBindings().get(9229));
        assertEquals(List.of(9229), spec.loopbackPortBindings());
        assertEquals(List.of("internal.test:host-gateway"), spec.extraHosts());
        assertEquals("lambda-net", spec.networkMode());
        assertEquals("1001:1001", spec.user());
        assertEquals(List.of("1.1.1.1"), spec.dnsServers());
        assertTrue(spec.privileged());
    }

    @Test
    void supportsEqualsSyntaxDynamicPortsAndReadWriteVolumes() {
        ContainerBuilder.Builder builder = builder();

        LambdaDockerFlags.apply(builder,
                "--env=MODE=local --volume=C:\\certs:/certs:rw --publish=8080 --dns=8.8.8.8");

        ContainerSpec spec = builder.build();
        assertEquals(List.of("MODE=local"), spec.env());
        assertEquals("C:\\certs", spec.binds().getFirst().getPath());
        assertEquals(AccessMode.rw, spec.binds().getFirst().getAccessMode());
        assertEquals(0, spec.portBindings().get(8080));
        assertEquals(List.of("8.8.8.8"), spec.dnsServers());
    }

    @Test
    void rejectsUnsupportedOrMalformedFlagsWithTheSettingNameInTheError() {
        IllegalArgumentException unsupported = assertThrows(IllegalArgumentException.class,
                () -> LambdaDockerFlags.apply(builder(), "--cap-add SYS_ADMIN"));
        assertTrue(unsupported.getMessage().contains("Invalid Lambda docker flags"));
        assertTrue(unsupported.getMessage().contains("unsupported flag --cap-add"));

        IllegalArgumentException malformedVolume = assertThrows(IllegalArgumentException.class,
                () -> LambdaDockerFlags.apply(builder(), "-v relative-only"));
        assertTrue(malformedVolume.getMessage().contains("HOST_PATH:CONTAINER_PATH"));

        IllegalArgumentException unterminated = assertThrows(IllegalArgumentException.class,
                () -> LambdaDockerFlags.apply(builder(), "-e 'MODE=local"));
        assertTrue(unterminated.getMessage().contains("unterminated quote"));
    }

    private static ContainerBuilder.Builder builder() {
        return new ContainerBuilder(null, null, null).newContainer("lambda-runtime:test");
    }
}
