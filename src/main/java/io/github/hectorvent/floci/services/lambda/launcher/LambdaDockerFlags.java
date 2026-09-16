package io.github.hectorvent.floci.services.lambda.launcher;

import io.github.hectorvent.floci.core.common.docker.ContainerBuilder;

import java.util.ArrayList;
import java.util.List;

/** Applies the supported LocalStack-compatible {@code LAMBDA_DOCKER_FLAGS} subset. */
final class LambdaDockerFlags {

    private LambdaDockerFlags() {
    }

    static void apply(ContainerBuilder.Builder builder, String rawFlags) {
        if (rawFlags == null || rawFlags.isBlank()) {
            return;
        }

        List<String> tokens = tokenize(rawFlags);
        for (int index = 0; index < tokens.size(); index++) {
            String token = tokens.get(index);
            String flag = token;
            String inlineValue = null;
            int equals = token.indexOf('=');
            if (equals > 0) {
                flag = token.substring(0, equals);
                inlineValue = token.substring(equals + 1);
            }

            switch (flag) {
                case "-e", "--env" -> {
                    String value = inlineValue != null ? inlineValue : nextValue(tokens, ++index, flag);
                    applyEnvironment(builder, value);
                }
                case "-v", "--volume" -> {
                    String value = inlineValue != null ? inlineValue : nextValue(tokens, ++index, flag);
                    applyVolume(builder, value);
                }
                case "-p", "--publish" -> {
                    String value = inlineValue != null ? inlineValue : nextValue(tokens, ++index, flag);
                    applyPublishedPort(builder, value);
                }
                case "--add-host" -> {
                    String value = inlineValue != null ? inlineValue : nextValue(tokens, ++index, flag);
                    applyExtraHost(builder, value);
                }
                case "--network" -> {
                    String value = inlineValue != null ? inlineValue : nextValue(tokens, ++index, flag);
                    builder.withNetworkMode(requireNonBlank(flag, value));
                }
                case "-u", "--user" -> {
                    String value = inlineValue != null ? inlineValue : nextValue(tokens, ++index, flag);
                    builder.withUser(requireNonBlank(flag, value));
                }
                case "--dns" -> {
                    String value = inlineValue != null ? inlineValue : nextValue(tokens, ++index, flag);
                    builder.withDnsServer(requireNonBlank(flag, value));
                }
                case "--privileged" -> {
                    if (inlineValue != null) {
                        throw invalid("--privileged does not take a value");
                    }
                    builder.withPrivileged(true);
                }
                default -> throw invalid("unsupported flag " + flag);
            }
        }
    }

    private static String nextValue(List<String> tokens, int index, String flag) {
        if (index >= tokens.size() || tokens.get(index).startsWith("-")) {
            throw invalid(flag + " requires a value");
        }
        return tokens.get(index);
    }

    private static String requireNonBlank(String flag, String value) {
        if (value == null || value.isBlank()) {
            throw invalid(flag + " requires a non-blank value");
        }
        return value;
    }

    private static void applyEnvironment(ContainerBuilder.Builder builder, String value) {
        int separator = value.indexOf('=');
        if (separator <= 0) {
            throw invalid("environment entries must use KEY=VALUE: " + value);
        }
        builder.withEnv(value.substring(0, separator), value.substring(separator + 1));
    }

    private static void applyVolume(ContainerBuilder.Builder builder, String value) {
        String mount = value;
        boolean readOnly = false;
        int lastSeparator = mount.lastIndexOf(':');
        if (lastSeparator > 0) {
            String suffix = mount.substring(lastSeparator + 1);
            if ("ro".equals(suffix) || "rw".equals(suffix)) {
                readOnly = "ro".equals(suffix);
                mount = mount.substring(0, lastSeparator);
            }
        }

        int pathSeparator = mount.lastIndexOf(':');
        if (pathSeparator <= 0 || pathSeparator == mount.length() - 1) {
            throw invalid("volume entries must use HOST_PATH:CONTAINER_PATH[:ro|rw]: " + value);
        }
        String hostPath = mount.substring(0, pathSeparator);
        String containerPath = mount.substring(pathSeparator + 1);
        if (!containerPath.startsWith("/")) {
            throw invalid("Lambda volume container paths must be absolute: " + value);
        }
        if (readOnly) {
            builder.withReadOnlyBind(hostPath, containerPath);
        } else {
            builder.withBind(hostPath, containerPath);
        }
    }

    private static void applyPublishedPort(ContainerBuilder.Builder builder, String value) {
        String mapping = value;
        int protocolSeparator = mapping.lastIndexOf('/');
        if (protocolSeparator >= 0) {
            String protocol = mapping.substring(protocolSeparator + 1);
            if (!"tcp".equalsIgnoreCase(protocol)) {
                throw invalid("only TCP Lambda port publishing is supported: " + value);
            }
            mapping = mapping.substring(0, protocolSeparator);
        }

        String[] parts = mapping.split(":", -1);
        try {
            if (parts.length == 1) {
                builder.withDynamicPort(Integer.parseInt(parts[0]));
                return;
            }
            if (parts.length == 2) {
                builder.withPortBinding(Integer.parseInt(parts[1]), parseHostPort(parts[0]));
                return;
            }
            if (parts.length == 3 && ("127.0.0.1".equals(parts[0]) || "0.0.0.0".equals(parts[0]))) {
                int containerPort = Integer.parseInt(parts[2]);
                int hostPort = parseHostPort(parts[1]);
                if ("127.0.0.1".equals(parts[0])) {
                    builder.withLoopbackPortBinding(containerPort, hostPort);
                } else {
                    builder.withPortBinding(containerPort, hostPort);
                }
                return;
            }
        } catch (NumberFormatException ignored) {
            // Fall through to the actionable error below.
        }
        throw invalid("port entries must use [127.0.0.1:]HOST_PORT:CONTAINER_PORT[/tcp]: " + value);
    }

    private static int parseHostPort(String value) {
        return value.isEmpty() ? 0 : Integer.parseInt(value);
    }

    private static void applyExtraHost(ContainerBuilder.Builder builder, String value) {
        int separator = value.indexOf(':');
        if (separator <= 0 || separator == value.length() - 1) {
            throw invalid("extra-host entries must use HOSTNAME:IP: " + value);
        }
        builder.withExtraHost(value.substring(0, separator), value.substring(separator + 1));
    }

    static List<String> tokenize(String rawFlags) {
        List<String> tokens = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        char quote = 0;
        boolean escaping = false;

        for (int index = 0; index < rawFlags.length(); index++) {
            char character = rawFlags.charAt(index);
            if (escaping) {
                current.append(character);
                escaping = false;
                continue;
            }
            if (character == '\\' && quote != '\'') {
                char next = index + 1 < rawFlags.length() ? rawFlags.charAt(index + 1) : 0;
                if (next == '\\' || next == quote || Character.isWhitespace(next)
                        || (quote == 0 && (next == '\'' || next == '"'))) {
                    escaping = true;
                } else {
                    current.append(character);
                }
                continue;
            }
            if (quote != 0) {
                if (character == quote) {
                    quote = 0;
                } else {
                    current.append(character);
                }
                continue;
            }
            if (character == '\'' || character == '"') {
                quote = character;
            } else if (Character.isWhitespace(character)) {
                if (!current.isEmpty()) {
                    tokens.add(current.toString());
                    current.setLength(0);
                }
            } else {
                current.append(character);
            }
        }

        if (escaping || quote != 0) {
            throw invalid("unterminated quote or escape");
        }
        if (!current.isEmpty()) {
            tokens.add(current.toString());
        }
        return tokens;
    }

    private static IllegalArgumentException invalid(String detail) {
        return new IllegalArgumentException("Invalid Lambda docker flags: " + detail);
    }
}
