/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics;

import org.opensearch.common.Randomness;
import org.opensearch.common.bytes.BytesReference;
import org.opensearch.common.xcontent.*;
import org.opensearch.commons.alerting.model.IntervalSchedule;
import org.opensearch.commons.alerting.model.Schedule;
import org.opensearch.commons.authuser.User;
import org.opensearch.securityanalytics.model.*;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.OpenSearchRestTestCase;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

public class TestHelpers {

    static class AccessRoles {
        static final String ALL_ACCESS_ROLE = "all_access";
    }

    public static Detector randomDetector() {
        return randomDetector(null, null, null, null, null, null, null, null);
    }

    public static Detector randomDetector(String name) {
        return randomDetector(name, null, null, null, null, null, null, null);
    }

    public static Detector randomDetector(String name, Detector.DetectorType detectorType) {
        return randomDetector(name, detectorType, null, null, null, null, null, null);
    }

    public static Detector randomDetector(String name, Detector.DetectorType detectorType, User user) {
        return randomDetector(name, detectorType, user, null, null, null, null, null);
    }

    public static Detector randomDetector(String name, Detector.DetectorType detectorType, User user, List<DetectorInput> inputs) {
        return randomDetector(name, detectorType, user, inputs, null, null, null, null);
    }

    public static Detector randomDetector(String name, Detector.DetectorType detectorType, User user, List<DetectorInput> inputs, Schedule schedule) {
        return randomDetector(name, detectorType, user, inputs, schedule, null, null, null);
    }

    public static Detector randomDetector(String name, Detector.DetectorType detectorType, User user, List<DetectorInput> inputs, Schedule schedule, Boolean enabled) {
        return randomDetector(name, detectorType, user, inputs, schedule, enabled, null, null);
    }

    public static Detector randomDetector(String name, Detector.DetectorType detectorType, User user, List<DetectorInput> inputs, Schedule schedule, Boolean enabled, Instant enabledTime) {
        return randomDetector(name, detectorType, user, inputs, schedule, enabled, enabledTime, null);
    }

    public static Detector randomDetector(String name,
                                          Detector.DetectorType detectorType,
                                          User user,
                                          List<DetectorInput> inputs,
                                          Schedule schedule,
                                          Boolean enabled,
                                          Instant enabledTime,
                                          Instant lastUpdateTime) {
        if (name == null) {
            name = OpenSearchRestTestCase.randomAlphaOfLength(10);
        }
        if (detectorType == null) {
            detectorType = Detector.DetectorType.valueOf(randomDetectorType().toUpperCase(Locale.ROOT));
        }
        if (user == null) {
            user = randomUser();
        }
        if (inputs == null) {
            inputs = Collections.emptyList();
        }
        if (schedule == null) {
            schedule = new IntervalSchedule(5, ChronoUnit.MINUTES, null);
        }
        if (enabled == null) {
            enabled = OpenSearchTestCase.randomBoolean();
        }
        if (enabledTime == null) {
            if (enabled) {
                enabledTime = Instant.now().truncatedTo(ChronoUnit.MILLIS);
            }
        }
        if (lastUpdateTime == null) {
            lastUpdateTime = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        }


        return new Detector(null, null, name, enabled, schedule, lastUpdateTime, enabledTime, detectorType, user, inputs, "");
    }

    public static Detector randomDetectorWithNoUser() {
        String name = OpenSearchRestTestCase.randomAlphaOfLength(10);
        Detector.DetectorType detectorType = Detector.DetectorType.valueOf(randomDetectorType().toUpperCase(Locale.ROOT));
        List<DetectorInput> inputs = Collections.emptyList();
        Schedule schedule = new IntervalSchedule(5, ChronoUnit.MINUTES, null);
        Boolean enabled = OpenSearchTestCase.randomBoolean();
        Instant enabledTime = enabled? Instant.now().truncatedTo(ChronoUnit.MILLIS): null;
        Instant lastUpdateTime = Instant.now().truncatedTo(ChronoUnit.MILLIS);

        return new Detector(null, null, name, enabled, schedule, lastUpdateTime, enabledTime, detectorType, null, inputs, "");
    }

    public static String toJsonStringWithUser(Detector detector) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        builder = detector.toXContentWithUser(builder, ToXContent.EMPTY_PARAMS);
        return BytesReference.bytes(builder).utf8ToString();
    }

    public static User randomUser() {
        return new User(
                OpenSearchRestTestCase.randomAlphaOfLength(10),
                List.of(
                        OpenSearchRestTestCase.randomAlphaOfLength(10),
                        OpenSearchRestTestCase.randomAlphaOfLength(10)
                ),
                List.of(OpenSearchRestTestCase.randomAlphaOfLength(10), AccessRoles.ALL_ACCESS_ROLE),
                List.of("test_attr=test")
        );
    }

    public static User randomUserEmpty() {
        return new User(
                "",
                List.of(),
                List.of(),
                List.of()
        );
    }

    public static String randomDetectorType() {
        List<String> detectorTypes = List.of("application", "apt");
        return detectorTypes.get(Randomness.get().nextInt(detectorTypes.size()));
    }

    public static DetectorRule randomDetectorRule() {
        String id = OpenSearchRestTestCase.randomAlphaOfLength(10);
        String rule = OpenSearchRestTestCase.randomAlphaOfLength(10);
        String name = String.valueOf(OpenSearchTestCase.randomInt(5));

        List<String> tags = new ArrayList<>();

        int start = 0;
        int end = OpenSearchTestCase.randomInt(10);
        for (int idx = start; idx <= end; ++idx) {
            tags.add(OpenSearchRestTestCase.randomAlphaOfLength(10));
        }

        return new DetectorRule(id, name, rule, tags);
    }

    public static XContentParser parser(String xc) throws IOException {
        XContentParser parser = XContentType.JSON.xContent().createParser(xContentRegistry(), LoggingDeprecationHandler.INSTANCE, xc);
        parser.nextToken();
        return parser;
    }

    public static NamedXContentRegistry xContentRegistry() {
        return new NamedXContentRegistry(
                List.of(
                        Detector.XCONTENT_REGISTRY,
                        DetectorInput.XCONTENT_REGISTRY
                )
        );
    }

    public static XContentBuilder builder() throws IOException {
        return XContentBuilder.builder(XContentType.JSON.xContent());
    }
}