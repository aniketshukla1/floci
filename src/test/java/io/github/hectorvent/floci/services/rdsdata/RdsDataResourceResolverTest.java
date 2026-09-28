package io.github.hectorvent.floci.services.rdsdata;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.AccountAwareStorageBackend;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.ec2.Ec2Service;
import io.github.hectorvent.floci.services.rds.RdsService;
import io.github.hectorvent.floci.services.rds.container.RdsContainerManager;
import io.github.hectorvent.floci.services.rds.model.DatabaseEngine;
import io.github.hectorvent.floci.services.rds.model.DbCluster;
import io.github.hectorvent.floci.services.rds.model.DbEndpoint;
import io.github.hectorvent.floci.services.rds.model.DbInstance;
import io.github.hectorvent.floci.services.rds.model.DbInstanceStatus;
import io.github.hectorvent.floci.services.rds.proxy.RdsProxyManager;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class RdsDataResourceResolverTest {

    @Test
    void resolvesClusterArnToContainerTarget() {
        RdsService rdsService = mock(RdsService.class);
        DbCluster cluster = new DbCluster("cluster1", DatabaseEngine.MYSQL, "8.0", "admin", "secret",
                "app", DbInstanceStatus.AVAILABLE, new DbEndpoint("localhost", 7001),
                new DbEndpoint("localhost", 7001), false, new ArrayList<>(), null, Instant.now(), 7001);
        cluster.setDbClusterArn("arn:aws:rds:us-east-1:000000000000:cluster:cluster1");
        cluster.setContainerHost("127.0.0.1");
        cluster.setContainerPort(3306);
        when(rdsService.getDbCluster("cluster1", "us-east-1")).thenReturn(cluster);
        when(rdsService.ensureClusterBackend("cluster1", "us-east-1")).thenReturn(cluster);

        RdsDataResourceResolver.DatabaseTarget target = new RdsDataResourceResolver(rdsService)
                .resolve("arn:aws:rds:us-east-1:000000000000:cluster:cluster1");

        assertEquals(DatabaseEngine.MYSQL, target.engine());
        assertEquals("127.0.0.1", target.host());
        assertEquals(3306, target.port());
        assertEquals("app", target.databaseName());
    }

    @Test
    void missingResourceUsesModeledDataApiBadRequestCode() {
        RdsService rdsService = mock(RdsService.class);
        when(rdsService.getDbCluster("missing", "us-east-1"))
                .thenThrow(new AwsException("DBClusterNotFoundFault", "missing", 404));

        AwsException error = assertThrows(AwsException.class, () -> new RdsDataResourceResolver(rdsService)
                .resolve("arn:aws:rds:us-east-1:000000000000:cluster:missing"));

        assertEquals("BadRequestException", error.getErrorCode());
        assertEquals(400, error.getHttpStatus());
    }

    @Test
    void dataApiNamesTheMissingDockerDaemonWhenTheInstanceHasNoBackingContainer() {
        RdsService rdsService = mock(RdsService.class);
        DbInstance instance = daemonlessInstance();
        when(rdsService.getDbInstance("probe-db", "us-east-1")).thenReturn(instance);
        when(rdsService.ensureInstanceBackend("probe-db", "us-east-1")).thenReturn(instance);
        when(rdsService.isBackendRuntimeAvailable()).thenReturn(false);

        AwsException error = assertThrows(AwsException.class, () -> new RdsDataResourceResolver(rdsService)
                .resolve("arn:aws:rds:us-east-1:000000000000:db:probe-db"));

        assertEquals("InternalServerErrorException", error.getErrorCode());
        assertEquals(500, error.getHttpStatus());
        assertTrue(error.getMessage().contains("Docker"), error.getMessage());
    }

    @Test
    void dataApiRetriesTheBackendSoItResolvesOnceADaemonAppears() {
        RdsService rdsService = mock(RdsService.class);
        DbInstance started = daemonlessInstance();
        started.setContainerHost("127.0.0.1");
        started.setContainerPort(5432);
        when(rdsService.getDbInstance("probe-db", "us-east-1")).thenReturn(daemonlessInstance());
        when(rdsService.ensureInstanceBackend("probe-db", "us-east-1")).thenReturn(started);

        RdsDataResourceResolver.DatabaseTarget target = new RdsDataResourceResolver(rdsService)
                .resolve("arn:aws:rds:us-east-1:000000000000:db:probe-db");

        assertEquals("127.0.0.1", target.host());
        assertEquals(5432, target.port());
    }

    @Test
    void dataApiRetriesAClusterBackendThroughTheClusterEntryPoint() {
        RdsService rdsService = mock(RdsService.class);
        DbCluster cluster = new DbCluster("cluster1", DatabaseEngine.POSTGRES, "16.3", "admin", "secret",
                "app", DbInstanceStatus.AVAILABLE, new DbEndpoint("localhost", 7001),
                new DbEndpoint("localhost", 7001), false, new ArrayList<>(), null, Instant.now(), 7001);
        cluster.setDbClusterArn("arn:aws:rds:us-east-1:000000000000:cluster:cluster1");
        DbCluster started = new DbCluster("cluster1", DatabaseEngine.POSTGRES, "16.3", "admin", "secret",
                "app", DbInstanceStatus.AVAILABLE, new DbEndpoint("localhost", 7001),
                new DbEndpoint("localhost", 7001), false, new ArrayList<>(), null, Instant.now(), 7001);
        started.setDbClusterArn(cluster.getDbClusterArn());
        started.setContainerHost("127.0.0.1");
        started.setContainerPort(5432);
        when(rdsService.getDbCluster("cluster1", "us-east-1")).thenReturn(cluster);
        when(rdsService.ensureClusterBackend("cluster1", "us-east-1")).thenReturn(started);

        RdsDataResourceResolver.DatabaseTarget target = new RdsDataResourceResolver(rdsService)
                .resolve("arn:aws:rds:us-east-1:000000000000:cluster:cluster1");

        assertEquals("127.0.0.1", target.host());
        assertEquals(5432, target.port());
    }

    @Test
    void repeatedClusterArnResolutionRetriesFailedMembersOfAnAlreadyRunningCluster() {
        EmulatorConfig config = mock(EmulatorConfig.class);
        EmulatorConfig.ServicesConfig servicesConfig = mock(EmulatorConfig.ServicesConfig.class);
        EmulatorConfig.RdsServiceConfig rdsConfig = mock(EmulatorConfig.RdsServiceConfig.class);
        when(config.services()).thenReturn(servicesConfig);
        when(config.defaultAccountId()).thenReturn("000000000000");
        when(servicesConfig.rds()).thenReturn(rdsConfig);
        when(rdsConfig.iamTokenEndpointBinding()).thenReturn(true);
        AccountAwareStorageBackend<DbCluster> clusters = AccountAwareStorageBackend.inMemory("000000000000");
        AccountAwareStorageBackend<DbInstance> instances = AccountAwareStorageBackend.inMemory("000000000000");
        StorageFactory storageFactory = mock(StorageFactory.class);
        when(storageFactory.create(anyString(), anyString(), any()))
                .thenAnswer(invocation -> AccountAwareStorageBackend.inMemory("000000000000"));
        when(storageFactory.<DbCluster>create(eq("rds"), eq("rds-clusters.json"), any())).thenReturn(clusters);
        when(storageFactory.<DbInstance>create(eq("rds"), eq("rds-instances.json"), any())).thenReturn(instances);
        DbCluster cluster = new DbCluster("cluster1", DatabaseEngine.POSTGRES, "16.3", "admin", "secret",
                "app", DbInstanceStatus.AVAILABLE, new DbEndpoint("localhost", 7001),
                new DbEndpoint("localhost", 7001), false, new ArrayList<>(), null, Instant.now(), 7001);
        cluster.setDbClusterArn("arn:aws:rds:us-west-2:000000000000:cluster:cluster1");
        cluster.setContainerId("cluster-container");
        cluster.setContainerHost("127.0.0.1");
        cluster.setContainerPort(15432);
        cluster.getDbClusterMembers().addAll(List.of("retry-member", "other-member", "stopped-member"));
        clusters.put("cluster1", cluster);
        DbInstance retryMember = clusterMember("retry-member", 7002, DbInstanceStatus.FAILED);
        DbInstance otherMember = clusterMember("other-member", 7003, DbInstanceStatus.AVAILABLE);
        DbInstance stoppedMember = clusterMember("stopped-member", 7004, DbInstanceStatus.STOPPED);
        instances.put("retry-member", retryMember);
        instances.put("other-member", otherMember);
        instances.put("stopped-member", stoppedMember);
        RdsContainerManager containers = mock(RdsContainerManager.class);
        RdsProxyManager proxies = mock(RdsProxyManager.class);
        doThrow(new IllegalStateException("temporary member relay error")).doNothing()
                .when(proxies).startProxy(eq("rds-resource:" + retryMember.getDbInstanceArn()),
                        any(), anyBoolean(), anyInt(), any(), anyInt(), any(), any(), any(), any(), any(), any());
        RdsService rdsService = new RdsService(containers, proxies, mock(Ec2Service.class),
                new RegionResolver("us-east-1", "000000000000"), config, storageFactory,
                null, null, null, null, null, null);
        RdsDataResourceResolver resolver = new RdsDataResourceResolver(rdsService);

        RdsDataResourceResolver.DatabaseTarget firstTarget = resolver.resolve(cluster.getDbClusterArn(), "us-west-2");

        assertEquals("127.0.0.1", firstTarget.host());
        assertEquals(15432, firstTarget.port());
        assertEquals(DbInstanceStatus.FAILED, retryMember.getStatus());
        assertEquals("cluster-container", otherMember.getContainerId());

        assertEquals(firstTarget, resolver.resolve(cluster.getDbClusterArn(), "us-west-2"));
        assertEquals(DbInstanceStatus.AVAILABLE, retryMember.getStatus());
        assertEquals("cluster-container", retryMember.getContainerId());
        assertEquals("127.0.0.1", retryMember.getContainerHost());
        assertEquals(15432, retryMember.getContainerPort());
        assertEquals(7002, retryMember.getEndpoint().port());
        assertEquals(firstTarget, resolver.resolve(cluster.getDbClusterArn(), "us-west-2"));
        assertEquals(DbInstanceStatus.STOPPED, stoppedMember.getStatus());
        verify(proxies, times(2)).startProxy(eq("rds-resource:" + retryMember.getDbInstanceArn()),
                any(), anyBoolean(), eq(7002), eq("127.0.0.1"), eq(15432), any(), any(), any(), any(), any(), any());
        verify(proxies).startProxy(eq("rds-resource:" + otherMember.getDbInstanceArn()),
                any(), anyBoolean(), eq(7003), eq("127.0.0.1"), eq(15432), any(), any(), any(), any(), any(), any());
        verify(proxies, never()).startProxy(eq("rds-resource:" + stoppedMember.getDbInstanceArn()),
                any(), anyBoolean(), anyInt(), any(), anyInt(), any(), any(), any(), any(), any(), any());
        verify(proxies, never()).startProxy(eq("rds-resource:" + cluster.getDbClusterArn()),
                any(), anyBoolean(), anyInt(), any(), anyInt(), any(), any(), any(), any(), any(), any());
        verifyNoInteractions(containers);
    }

    private static DbInstance clusterMember(String id, int port, DbInstanceStatus status) {
        DbInstance instance = new DbInstance(id, DatabaseEngine.POSTGRES, "16.3", "admin", "secret",
                "app", "db.serverless", 0, status, new DbEndpoint("localhost", port),
                false, null, null, Instant.now(), port);
        instance.setDbInstanceArn("arn:aws:rds:us-west-2:000000000000:db:" + id);
        instance.setDbClusterIdentifier("cluster1");
        return instance;
    }

    private static DbInstance daemonlessInstance() {
        DbInstance instance = new DbInstance("probe-db", DatabaseEngine.POSTGRES, "16.3", "admin",
                "secret", "app", "db.t3.micro", 20, DbInstanceStatus.AVAILABLE,
                new DbEndpoint("localhost", 7001), false, null, null, Instant.now(), 7001);
        instance.setDbInstanceArn("arn:aws:rds:us-east-1:000000000000:db:probe-db");
        return instance;
    }

    @Test
    void rejectsResourceArnOutsideSignedRequestRegionBeforeLookup() {
        RdsService rdsService = mock(RdsService.class);

        AwsException error = assertThrows(AwsException.class, () ->
                new RdsDataResourceResolver(rdsService).resolve(
                        "arn:aws:rds:us-west-2:000000000000:cluster:cluster1",
                        "us-east-1"));

        assertEquals("BadRequestException", error.getErrorCode());
        assertEquals(400, error.getHttpStatus());
        org.mockito.Mockito.verifyNoInteractions(rdsService);
    }
}
