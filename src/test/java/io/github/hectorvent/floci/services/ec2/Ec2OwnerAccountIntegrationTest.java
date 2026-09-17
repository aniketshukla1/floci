package io.github.hectorvent.floci.services.ec2;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

import java.util.UUID;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;

@QuarkusTest
class Ec2OwnerAccountIntegrationTest {

    private static final String ACCOUNT_ID = "444444444444";
    private static final String DEFAULT_ACCOUNT_ID = "000000000000";
    private static final String AUTH_HEADER =
            "AWS4-HMAC-SHA256 Credential=" + ACCOUNT_ID + "/20260917/us-east-1/ec2/aws4_request";

    @Test
    void reportsTheRequestAccountAsTheOwnerOfCreatedResources() {
        String suffix = UUID.randomUUID().toString();
        String imageId = given()
            .formParam("Action", "RegisterImage")
            .formParam("Name", "request-account-image-" + suffix)
            .formParam("Architecture", "x86_64")
            .formParam("RootDeviceName", "/dev/sda1")
            .header("Authorization", AUTH_HEADER)
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .extract().path("RegisterImageResponse.imageId");

        String securityGroupId = given()
            .formParam("Action", "CreateSecurityGroup")
            .formParam("GroupName", "request-account-sg-" + suffix)
            .formParam("GroupDescription", "Request account owner test")
            .header("Authorization", AUTH_HEADER)
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .extract().path("CreateSecurityGroupResponse.groupId");

        given()
            .formParam("Action", "DescribeImages")
            .formParam("ImageId.1", imageId)
            .formParam("Owner.1", ACCOUNT_ID)
            .header("Authorization", AUTH_HEADER)
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("DescribeImagesResponse.imagesSet.item.size()", equalTo(1))
            .body("DescribeImagesResponse.imagesSet.item.imageOwnerId", equalTo(ACCOUNT_ID));

        given()
            .formParam("Action", "DescribeImages")
            .formParam("ImageId.1", imageId)
            .formParam("Owner.1", DEFAULT_ACCOUNT_ID)
            .header("Authorization", AUTH_HEADER)
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("DescribeImagesResponse.imagesSet.item.size()", equalTo(0));

        given()
            .formParam("Action", "DescribeSecurityGroups")
            .formParam("GroupId.1", securityGroupId)
            .header("Authorization", AUTH_HEADER)
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("DescribeSecurityGroupsResponse.securityGroupInfo.item.ownerId", equalTo(ACCOUNT_ID));
    }
}
