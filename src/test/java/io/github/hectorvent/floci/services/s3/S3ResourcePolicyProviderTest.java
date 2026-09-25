package io.github.hectorvent.floci.services.s3;

import io.github.hectorvent.floci.testing.PartitionMatrix.PartitionCase;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * The bucket-policy lookup is on the authorization path: a bucket ARN whose partition the
 * provider does not recognise finds no policy, which silently flips an allow or a deny.
 */
class S3ResourcePolicyProviderTest {

    @ParameterizedTest
    @MethodSource("io.github.hectorvent.floci.testing.PartitionMatrix#cases")
    void bucketIsExtractedFromAnS3ArnInEveryPartition(PartitionCase partitionCase) {
        String prefix = "arn:" + partitionCase.partition() + ":s3:::";
        assertEquals("audit-source", S3ResourcePolicyProvider.extractBucketName(prefix + "audit-source"));
        assertEquals("audit-source", S3ResourcePolicyProvider.extractBucketName(prefix + "audit-source/documents/hello.txt"));
        assertEquals("*", S3ResourcePolicyProvider.extractBucketName(prefix + "*"));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"arn:aws:lambda:us-east-1:000000000000:function:f", "audit-source", "arn:aws:s3"})
    void nonS3ArnsYieldNoBucket(String value) {
        assertNull(S3ResourcePolicyProvider.extractBucketName(value));
    }
}
