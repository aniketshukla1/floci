package com.floci.test;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.services.cloudformation.CloudFormationClient;
import software.amazon.awssdk.services.cloudformation.model.ChangeSetType;
import software.amazon.awssdk.services.cloudformation.model.CloudFormationException;
import software.amazon.awssdk.services.cloudformation.model.Stack;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CloudFormationChangeSetArnTest {

    private static final String TEMPLATE = "Resources:\n  Queue:\n    Type: AWS::SQS::Queue\n";
    private static CloudFormationClient cloudFormation;

    private final List<String> stacksToDelete = new ArrayList<>();

    @BeforeAll
    static void createClient() {
        cloudFormation = TestFixtures.cloudFormationClient();
    }

    @AfterAll
    static void closeClient() {
        cloudFormation.close();
    }

    @AfterEach
    void deleteStacks() {
        for (String stackName : stacksToDelete) {
            try {
                cloudFormation.deleteStack(request -> request.stackName(stackName));
            } catch (CloudFormationException ignored) {
                // A failed assertion may leave a change set without a stack to delete.
            }
        }
    }

    @Test
    void sdkResolvesChangeSetArnWithoutStackNameAndExecutesItsStack() throws InterruptedException {
        String firstStack = newStackName();
        String secondStack = newStackName();
        String firstArn = createChangeSet(firstStack);
        String secondArn = createChangeSet(secondStack);

        assertThat(firstArn).isNotEqualTo(secondArn);
        assertThat(cloudFormation.describeChangeSet(request -> request.changeSetName(secondArn)).stackName())
                .isEqualTo(secondStack);
        assertThat(cloudFormation.describeChangeSet(request -> request.changeSetName(firstArn)).stackName())
                .isEqualTo(firstStack);

        cloudFormation.executeChangeSet(request -> request.changeSetName(secondArn));
        awaitStackCreated(secondStack);
        assertThat(cloudFormation.describeStackResource(request -> request.stackName(secondStack)
                .logicalResourceId("Queue")).stackResourceDetail().resourceStatusAsString())
                .isEqualTo("CREATE_COMPLETE");
        assertThat(cloudFormation.describeChangeSet(request -> request.changeSetName(secondArn))
                .executionStatusAsString()).isEqualTo("EXECUTE_COMPLETE");

        cloudFormation.deleteChangeSet(request -> request.changeSetName(firstArn));
        assertThatThrownBy(() -> cloudFormation.describeChangeSet(request -> request.changeSetName(firstArn)))
                .isInstanceOf(CloudFormationException.class)
                .satisfies(error -> assertThat(((CloudFormationException) error).awsErrorDetails().errorCode())
                        .isEqualTo("ChangeSetNotFoundException"));
    }

    private String newStackName() {
        String stackName = TestFixtures.uniqueName("cfn-arn-sdk");
        stacksToDelete.add(stackName);
        return stackName;
    }

    private static String createChangeSet(String stackName) {
        return cloudFormation.createChangeSet(request -> request.stackName(stackName)
                .changeSetName("shared-name").changeSetType(ChangeSetType.CREATE)
                .templateBody(TEMPLATE)).id();
    }

    private static void awaitStackCreated(String stackName) throws InterruptedException {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
        while (System.nanoTime() < deadline) {
            Stack stack = cloudFormation.describeStacks(request -> request.stackName(stackName)).stacks().get(0);
            String status = stack.stackStatusAsString();
            if ("CREATE_COMPLETE".equals(status)) {
                return;
            }
            if (status.endsWith("_FAILED") || status.contains("ROLLBACK")) {
                throw new AssertionError(stackName + " reached " + status + ": " + stack.stackStatusReason());
            }
            Thread.sleep(100);
        }
        throw new AssertionError(stackName + " did not reach CREATE_COMPLETE within 60 seconds");
    }
}
