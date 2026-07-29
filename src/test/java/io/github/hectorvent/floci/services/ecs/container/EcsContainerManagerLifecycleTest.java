package io.github.hectorvent.floci.services.ecs.container;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.RemoveContainerCmd;
import com.github.dockerjava.api.command.StopContainerCmd;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.common.docker.ContainerBuilder;
import io.github.hectorvent.floci.core.common.docker.ContainerDetector;
import io.github.hectorvent.floci.core.common.docker.ContainerLifecycleManager;
import io.github.hectorvent.floci.core.common.docker.ContainerLogStreamer;
import io.github.hectorvent.floci.core.common.docker.LaunchedContainerAwsEnv;
import io.github.hectorvent.floci.services.secretsmanager.SecretsManagerService;
import io.github.hectorvent.floci.services.ssm.SsmService;
import org.junit.jupiter.api.Test;

import java.io.Closeable;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class EcsContainerManagerLifecycleTest {

    @Test
    void finalizesTaskLogStreamsAfterForceRemovingAContainerWhoseStopFails() {
        ContainerLifecycleManager lifecycleManager = mock(ContainerLifecycleManager.class);
        DockerClient dockerClient = mock(DockerClient.class);
        StopContainerCmd stop = mock(StopContainerCmd.class);
        RemoveContainerCmd remove = mock(RemoveContainerCmd.class);
        Closeable logStream = mock(Closeable.class);
        when(lifecycleManager.getDockerClient()).thenReturn(dockerClient);
        when(dockerClient.stopContainerCmd("docker-id")).thenReturn(stop);
        when(stop.withTimeout(5)).thenReturn(stop);
        when(dockerClient.removeContainerCmd("docker-id")).thenReturn(remove);
        when(remove.withForce(true)).thenReturn(remove);
        doThrow(new RuntimeException("Docker daemon unavailable")).when(stop).exec();

        EcsContainerManager manager = manager(lifecycleManager);
        EcsTaskHandle handle = new EcsTaskHandle("task-arn", Map.of("app", "docker-id"), List.of(logStream));

        manager.stopTaskAndCollectExitCodes(handle);

        verify(remove).exec();
        verify(lifecycleManager).closeLogStreamAfterContainerStop(logStream);
    }

    @Test
    void finalizesTaskLogStreamsAfterEveryContainerStops() {
        ContainerLifecycleManager lifecycleManager = mock(ContainerLifecycleManager.class);
        DockerClient dockerClient = mock(DockerClient.class);
        StopContainerCmd stop = mock(StopContainerCmd.class);
        RemoveContainerCmd remove = mock(RemoveContainerCmd.class);
        Closeable logStream = mock(Closeable.class);
        when(lifecycleManager.getDockerClient()).thenReturn(dockerClient);
        when(dockerClient.stopContainerCmd("docker-id")).thenReturn(stop);
        when(stop.withTimeout(5)).thenReturn(stop);
        when(dockerClient.removeContainerCmd("docker-id")).thenReturn(remove);
        when(remove.withForce(true)).thenReturn(remove);

        EcsContainerManager manager = manager(lifecycleManager);
        EcsTaskHandle handle = new EcsTaskHandle("task-arn", Map.of("app", "docker-id"), List.of(logStream));

        manager.stopTaskAndCollectExitCodes(handle);

        verify(lifecycleManager).closeLogStreamAfterContainerStop(logStream);
    }

    private static EcsContainerManager manager(ContainerLifecycleManager lifecycleManager) {
        return new EcsContainerManager(
                mock(ContainerBuilder.class), lifecycleManager, mock(ContainerLogStreamer.class),
                mock(ContainerDetector.class), mock(EmulatorConfig.class), mock(RegionResolver.class),
                mock(LaunchedContainerAwsEnv.class), mock(SsmService.class), mock(SecretsManagerService.class));
    }
}
