package com.floci.test;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.FunctionCode;
import software.amazon.awssdk.services.lambda.model.GetFunctionResponse;
import software.amazon.awssdk.services.lambda.model.Runtime;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("Lambda - GetFunction reserved concurrency")
class LambdaGetFunctionConcurrencyTest {

    private LambdaClient lambda;
    private String functionName;

    @BeforeEach
    void setup() {
        lambda = TestFixtures.lambdaClient();
        functionName = TestFixtures.uniqueName("sdk-get-concurrency");
        lambda.createFunction(request -> request.functionName(functionName)
                .runtime(Runtime.NODEJS20_X)
                .role("arn:aws:iam::000000000000:role/lambda-role")
                .handler("index.handler")
                .code(FunctionCode.builder().zipFile(SdkBytes.fromByteArray(LambdaUtils.minimalZip())).build()));
    }

    @AfterEach
    void cleanup() {
        try {
            lambda.deleteFunction(request -> request.functionName(functionName));
        } finally {
            lambda.close();
        }
    }

    @Test
    void getFunctionRoundTripsReservationUpdatesZeroAndDeletion() {
        assertThat(lambda.getFunction(request -> request.functionName(functionName)).concurrency()).isNull();

        for (int reservation : new int[]{2, 7, 0}) {
            lambda.putFunctionConcurrency(request -> request.functionName(functionName)
                    .reservedConcurrentExecutions(reservation));
            GetFunctionResponse response = lambda.getFunction(request -> request.functionName(functionName));
            assertThat(response.concurrency()).isNotNull();
            assertThat(response.concurrency().reservedConcurrentExecutions()).isEqualTo(reservation);
            assertThat(response.configuration().functionName()).isEqualTo(functionName);
            assertThat(response.code().location()).isNotBlank();
        }

        lambda.deleteFunctionConcurrency(request -> request.functionName(functionName));
        assertThat(lambda.getFunction(request -> request.functionName(functionName)).concurrency()).isNull();
    }

    @Test
    void versionsAliasesAndQualifiedArnsUseTheCurrentFunctionWideReservation() {
        lambda.putFunctionConcurrency(request -> request.functionName(functionName).reservedConcurrentExecutions(2));
        String version = lambda.publishVersion(request -> request.functionName(functionName)).version();
        lambda.createAlias(request -> request.functionName(functionName).name("live").functionVersion(version));
        String functionArn = lambda.getFunction(request -> request.functionName(functionName))
                .configuration().functionArn();

        for (int reservation : new int[]{7, 0}) {
            lambda.putFunctionConcurrency(request -> request.functionName(functionName)
                    .reservedConcurrentExecutions(reservation));
            for (String qualifier : new String[]{version, "live"}) {
                GetFunctionResponse response = lambda.getFunction(request -> request.functionName(functionName)
                        .qualifier(qualifier));
                assertThat(response.configuration().version()).isEqualTo(version);
                assertThat(response.concurrency()).isNotNull();
                assertThat(response.concurrency().reservedConcurrentExecutions()).isEqualTo(reservation);
            }
            GetFunctionResponse byArn = lambda.getFunction(request -> request.functionName(functionArn + ":live"));
            assertThat(byArn.concurrency()).isNotNull();
            assertThat(byArn.concurrency().reservedConcurrentExecutions()).isEqualTo(reservation);
        }

        lambda.deleteFunctionConcurrency(request -> request.functionName(functionName));
        assertThat(lambda.getFunction(request -> request.functionName(functionName).qualifier(version))
                .concurrency()).isNull();
        assertThat(lambda.getFunction(request -> request.functionName(functionArn + ":live"))
                .concurrency()).isNull();
    }
}
