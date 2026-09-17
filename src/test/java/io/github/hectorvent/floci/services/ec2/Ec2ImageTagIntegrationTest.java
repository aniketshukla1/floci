package io.github.hectorvent.floci.services.ec2;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

import java.util.UUID;

import org.junit.jupiter.api.Test;

import io.quarkus.test.junit.QuarkusTest;

@QuarkusTest
class Ec2ImageTagIntegrationTest {

    private static final String AUTH_HEADER =
            "AWS4-HMAC-SHA256 Credential=111111111111/20260917/us-east-1/ec2/aws4_request";

    @Test
    void returnsImageTagsAndAppliesTagFilters() {
        String suffix = UUID.randomUUID().toString();
        String tagValue = "Packer-" + suffix;
        String imageId = given()
            .formParam("Action", "RegisterImage")
            .formParam("Name", "tagged-image-" + suffix)
            .formParam("Architecture", "x86_64")
            .formParam("RootDeviceName", "/dev/xvda")
            .header("Authorization", AUTH_HEADER)
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .extract().path("RegisterImageResponse.imageId");

        given()
            .formParam("Action", "CreateTags")
            .formParam("ResourceId.1", imageId)
            .formParam("Tag.1.Key", "Origin")
            .formParam("Tag.1.Value", tagValue)
            .header("Authorization", AUTH_HEADER)
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("CreateTagsResponse.return", equalTo("true"));

        given()
            .formParam("Action", "DescribeImages")
            .formParam("ImageId.1", imageId)
            .header("Authorization", AUTH_HEADER)
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("DescribeImagesResponse.imagesSet.item.tagSet.item.key", equalTo("Origin"))
            .body("DescribeImagesResponse.imagesSet.item.tagSet.item.value", equalTo(tagValue));

        given()
            .formParam("Action", "DescribeImages")
            .formParam("Filter.1.Name", "tag:Origin")
            .formParam("Filter.1.Value.1", tagValue)
            .header("Authorization", AUTH_HEADER)
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("DescribeImagesResponse.imagesSet.item.size()", equalTo(1))
            .body("DescribeImagesResponse.imagesSet.item.imageId", equalTo(imageId));

        given()
            .formParam("Action", "DescribeImages")
            .formParam("Filter.1.Name", "tag:Origin")
            .formParam("Filter.1.Value.1", "DOES-NOT-EXIST")
            .header("Authorization", AUTH_HEADER)
        .when()
            .post("/")
        .then()
            .statusCode(200)
            .body("DescribeImagesResponse.imagesSet.item.size()", equalTo(0));
    }
}
