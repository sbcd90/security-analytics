/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import org.opensearch.common.ParseField;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.common.xcontent.*;
import org.opensearch.commons.authuser.User;

import java.io.IOException;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

public class Detector implements Writeable, ToXContentObject {

    private static final String DETECTOR_TYPE = "detector";
    private static final String TYPE_FIELD = "type";
    private static final String DETECTOR_TYPE_FIELD = "detector_type";
    private static final String NAME_FIELD = "name";
    private static final String USER_FIELD = "user";
    private static final String ENABLED_FIELD = "enabled";
    private static final String SCHEDULE_FIELD = "schedule";
    private static final String NO_ID = "";
    private static final Long NO_VERSION = 1L;
    private static final String INPUTS_FIELD = "inputs";
    private static final String LAST_UPDATE_TIME_FIELD = "last_update_time";
    private static final String ENABLED_TIME_FIELD = "enabled_time";

    public static final String DETECTORS_INDEX = ".opensearch-detectors-config";

    public static final NamedXContentRegistry.Entry XCONTENT_REGISTRY = new NamedXContentRegistry.Entry(
            Detector.class,
            new ParseField(DETECTOR_TYPE),
            xcp -> parse(xcp, null, null)
    );

    private String id;

    private Long version;

    private String name;

    private Boolean enabled;

    private Schedule schedule;

    private Instant lastUpdateTime;

    private Instant enabledTime;

    private DetectorType detectorType;

    private User user;

    private List<DetectorInput> inputs;

    private final String type;

    public Detector(String id, Long version, String name, Boolean enabled, Schedule schedule,
                    Instant lastUpdateTime, Instant enabledTime, DetectorType detectorType,
                    User user, List<DetectorInput> inputs) {
        this.type = DETECTOR_TYPE;

        this.id = id != null? id: NO_ID;
        this.version = version != null? version: NO_VERSION;
        this.name = name;
        this.enabled = enabled;
        this.schedule = schedule;
        this.lastUpdateTime = lastUpdateTime;
        this.enabledTime = enabledTime;
        this.detectorType = detectorType;
        this.user = user;
        this.inputs = inputs;

        if (enabled) {
            Objects.requireNonNull(enabledTime);
        }
    }

    public Detector(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readLong(),
                sin.readString(),
                sin.readBoolean(),
                Schedule.readFrom(sin),
                sin.readInstant(),
                sin.readOptionalInstant(),
                sin.readEnum(DetectorType.class),
                sin.readBoolean()? new User(sin): null,
                sin.readList(DetectorInput::readFrom)
        );
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(id);
        out.writeLong(version);
        out.writeString(name);
        out.writeBoolean(enabled);
        if (schedule instanceof CronSchedule) {
            out.writeEnum(Schedule.TYPE.CRON);
        } else {
            out.writeEnum(Schedule.TYPE.INTERVAL);
        }
        schedule.writeTo(out);
        out.writeInstant(lastUpdateTime);
        out.writeOptionalInstant(enabledTime);
        out.writeEnum(detectorType);
        out.writeBoolean(user != null);
        if (user != null) {
            user.writeTo(out);
        }
        out.writeVInt(inputs.size());
        for (DetectorInput it: inputs) {
            it.writeTo(out);
        }
    }

    public XContentBuilder toXContentWithUser(XContentBuilder builder, Params params) throws IOException {
        return createXContentBuilder(builder, params, false);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return createXContentBuilder(builder, params, true);
    }

    enum DetectorType {
        APPLICATION,
        APT,
        CLOUD,
        COMPLIANCE,
        LINUX,
        MACOS,
        NETWORK,
        PROXY,
        WEB,
        WINDOWS;

        String getDetectorType() throws IOException {
            switch (this) {
                case APPLICATION:
                    return "application";
                case APT:
                    return "apt";
                case CLOUD:
                    return "cloud";
                case COMPLIANCE:
                    return "compliance";
                case LINUX:
                    return "linux";
                case MACOS:
                    return "macos";
                case NETWORK:
                    return "network";
                case PROXY:
                    return "proxy";
                case WEB:
                    return "web";
                case WINDOWS:
                    return "windows";
                default:
                    throw new IOException(String.format(Locale.getDefault(), "Detector Type %s not found", this.name()));
            }
        }
    }

    private XContentBuilder createXContentBuilder(XContentBuilder builder, ToXContent.Params params, Boolean secure) throws IOException {
        builder.startObject();
        if (params.paramAsBoolean("with_type", false)) {
            builder.startObject(type);
        }
        builder.field(TYPE_FIELD, type)
                .field(NAME_FIELD, name)
                .field(DETECTOR_TYPE_FIELD, detectorType);

        if (!secure) {
            if (user == null) {
                builder.nullField(USER_FIELD);
            } else {
                builder.field(USER_FIELD, user);
            }
        }

        builder.field(ENABLED_FIELD, enabled);

        if (enabledTime == null) {
            builder.nullField(ENABLED_TIME_FIELD);
        } else {
            builder.timeField(ENABLED_TIME_FIELD, String.format(Locale.getDefault(), "%s_in_millis", enabledTime.toEpochMilli()));
        }

        builder.field(SCHEDULE_FIELD, schedule);

        DetectorInput[] inputsArray = new DetectorInput[]{};
        inputsArray = inputs.toArray(inputsArray);
        builder.field(INPUTS_FIELD, inputsArray);

        if (lastUpdateTime == null) {
            builder.nullField(LAST_UPDATE_TIME_FIELD);
        } else {
            builder.timeField(LAST_UPDATE_TIME_FIELD, String.format(Locale.getDefault(), "%s_in_millis", lastUpdateTime.toEpochMilli()));
        }

        if (params.paramAsBoolean("with_type", false)) {
            builder.endObject();
        }
        return builder.endObject();
    }

    public static Detector parse(XContentParser xcp, String id, Long version) throws IOException {
        if (id == null) {
            id = NO_ID;
        }
        if (version == null) {
            version = NO_VERSION;
        }

        String name = null;
        String detectorType = null;
        User user = null;
        Schedule schedule = null;
        Instant lastUpdateTime = null;
        Instant enabledTime = null;
        Boolean enabled = true;
        List<DetectorInput> inputs = new ArrayList<>();

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = xcp.currentName();
            xcp.nextToken();

            switch (fieldName) {
                case NAME_FIELD:
                    name = xcp.text();
                    break;
                case DETECTOR_TYPE_FIELD:
                    detectorType = xcp.text();
                    List<String> allowedTypes = Arrays.stream(DetectorType.values()).map(it -> {
                        try {
                            return it.getDetectorType();
                        } catch (IOException e) {
                            return null;
                        }
                    }).collect(Collectors.toList());

                    if (!allowedTypes.contains(detectorType)) {
                        throw new IllegalStateException("Monitor type should be one of ");
                    }
                    break;
                case USER_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        user = null;
                    } else {
                        user = User.parse(xcp);
                    }
                    break;
                case ENABLED_FIELD:
                    enabled = xcp.booleanValue();
                    break;
                case SCHEDULE_FIELD:
                    schedule = Schedule.parse(xcp);
                    break;
                case INPUTS_FIELD:
                    XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_ARRAY, xcp.currentToken(), xcp);
                    while (xcp.nextToken() != XContentParser.Token.END_ARRAY) {
                        DetectorInput input = DetectorInput.parse(xcp);
                        inputs.add(input);
                    }
                    break;
                case ENABLED_TIME_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        enabledTime = null;
                    } else if (xcp.currentToken().isValue()) {
                        enabledTime = Instant.ofEpochMilli(xcp.longValue());
                    } else {
                        XContentParserUtils.throwUnknownToken(xcp.currentToken(), xcp.getTokenLocation());
                        enabledTime = null;
                    }
                    break;
                case LAST_UPDATE_TIME_FIELD:
                    if (xcp.currentToken() == XContentParser.Token.VALUE_NULL) {
                        lastUpdateTime = null;
                    } else if (xcp.currentToken().isValue()) {
                        lastUpdateTime = Instant.ofEpochMilli(xcp.longValue());
                    } else {
                        XContentParserUtils.throwUnknownToken(xcp.currentToken(), xcp.getTokenLocation());
                        lastUpdateTime = null;
                    }
                    break;
                default:
                    xcp.skipChildren();
            }
        }

        if (enabled && enabledTime == null) {
            enabledTime = Instant.now();
        } else if (!enabled) {
            enabledTime = null;
        }

        return new Detector(
                    id,
                    version,
                    Objects.requireNonNull(name, "Detector name is null"),
                    enabled,
                    Objects.requireNonNull(schedule, "Detector schedule is null"),
                    lastUpdateTime != null? lastUpdateTime: Instant.now(),
                    enabledTime,
                    DetectorType.valueOf(detectorType.toUpperCase(Locale.ROOT)),
                    user,
                    inputs
                );
    }

    public static Detector readFrom(StreamInput sin) throws IOException {
        return new Detector(sin);
    }

    public String getDetectorType() throws IOException {
        return detectorType.getDetectorType();
    }

    public List<DetectorInput> getInputs() {
        return inputs;
    }
}