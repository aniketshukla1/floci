package io.github.hectorvent.floci.services.rds;

import io.github.hectorvent.floci.testing.RdsMockProfile;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.specification.RequestSpecification;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static io.restassured.http.ContentType.URLENC;
import static org.hamcrest.Matchers.containsString;

/** RestoreDBClusterFromSnapshot must expose the requested connection port on the wire. */
@QuarkusTest
@TestProfile(RdsMockProfile.class)
class RdsClusterSnapshotRestorePortIntegrationTest {

    private static final String SOURCE = "restore-port-source";
    private static final String SNAPSHOT = "restore-port-snapshot";
    private static final String RESTORED = "restore-port-target";

    private static RequestSpecification rds(String action) {
        return given().header("Authorization",
                        "AWS4-HMAC-SHA256 Credential=test/20260924/us-east-1/rds/aws4_request, "
                        + "SignedHeaders=content-type;host, Signature=test")
                .contentType(URLENC)
                .formParam("Action", action)
                .formParam("Version", "2014-10-31");
    }

    @AfterEach
    void cleanUp() {
        for (String id : new String[]{RESTORED, SOURCE}) {
            rds("DeleteDBCluster").formParam("DBClusterIdentifier", id)
                    .formParam("SkipFinalSnapshot", "true").when().post("/");
        }
        rds("DeleteDBClusterSnapshot").formParam("DBClusterSnapshotIdentifier", SNAPSHOT)
                .when().post("/");
    }

    @Test
    void requestedPortIsUsedInRestoreResponseAndDescribe() {
        rds("CreateDBCluster")
                .formParam("DBClusterIdentifier", SOURCE)
                .formParam("Engine", "aurora-postgresql")
                .formParam("EngineVersion", "16.3")
                .formParam("MasterUsername", "admin")
                .formParam("MasterUserPassword", "password123")
                .when().post("/").then().statusCode(200);
        rds("CreateDBClusterSnapshot")
                .formParam("DBClusterIdentifier", SOURCE)
                .formParam("DBClusterSnapshotIdentifier", SNAPSHOT)
                .when().post("/").then().statusCode(200);

        rds("RestoreDBClusterFromSnapshot")
                .formParam("DBClusterIdentifier", RESTORED)
                .formParam("SnapshotIdentifier", SNAPSHOT)
                .formParam("Engine", "aurora-postgresql")
                .formParam("Port", "15432")
                .when().post("/").then().statusCode(200)
                .body(containsString("<Port>15432</Port>"));

        rds("DescribeDBClusters")
                .formParam("DBClusterIdentifier", RESTORED)
                .when().post("/").then().statusCode(200)
                .body(containsString("<Port>15432</Port>"));
    }
}
