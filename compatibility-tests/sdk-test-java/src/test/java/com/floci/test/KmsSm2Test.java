package com.floci.test;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.kms.KmsClient;
import software.amazon.awssdk.services.kms.model.KeySpec;
import software.amazon.awssdk.services.kms.model.KeyUsageType;
import software.amazon.awssdk.services.kms.model.MessageType;
import software.amazon.awssdk.services.kms.model.SigningAlgorithmSpec;

import static org.assertj.core.api.Assertions.assertThat;

class KmsSm2Test {

    @ParameterizedTest
    @ValueSource(strings = {"cn-north-1", "cn-northwest-1"})
    void signAndVerifyUseSm2dsaWireAlgorithm(String region) {
        try (KmsClient kms = TestFixtures.kmsClient(Region.of(region))) {
            var key = kms.createKey(b -> b.keySpec(KeySpec.SM2).keyUsage(KeyUsageType.SIGN_VERIFY));
            String keyId = key.keyMetadata().keyId();
            try {
                assertThat(key.keyMetadata().signingAlgorithms()).containsExactly(SigningAlgorithmSpec.SM2_DSA);
                var publicKey = kms.getPublicKey(b -> b.keyId(keyId));
                assertThat(publicKey.signingAlgorithms()).containsExactly(SigningAlgorithmSpec.SM2_DSA);
                assertThat(publicKey.publicKey().asByteArray()).isNotEmpty();

                var message = SdkBytes.fromUtf8String("SM2 SDK wire compatibility");
                var signed = kms.sign(b -> b.keyId(keyId)
                        .message(message)
                        .messageType(MessageType.RAW)
                        .signingAlgorithm(SigningAlgorithmSpec.SM2_DSA));
                assertThat(signed.signingAlgorithm()).isEqualTo(SigningAlgorithmSpec.SM2_DSA);
                assertThat(signed.signingAlgorithmAsString()).isEqualTo("SM2DSA");
                assertThat(signed.signature().asByteArray()).isNotEmpty();

                var verified = kms.verify(b -> b.keyId(keyId)
                        .message(message)
                        .messageType(MessageType.RAW)
                        .signature(signed.signature())
                        .signingAlgorithm(SigningAlgorithmSpec.SM2_DSA));
                assertThat(verified.signingAlgorithm()).isEqualTo(SigningAlgorithmSpec.SM2_DSA);
                assertThat(verified.signingAlgorithmAsString()).isEqualTo("SM2DSA");
                assertThat(verified.signatureValid()).isTrue();
            } finally {
                kms.scheduleKeyDeletion(b -> b.keyId(keyId).pendingWindowInDays(7));
            }
        }
    }
}
