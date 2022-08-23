/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import com.cronutils.model.time.ExecutionTime;
import org.apache.commons.lang3.tuple.Pair;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.StreamOutput;
import org.opensearch.common.xcontent.XContentBuilder;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.chrono.ChronoZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

public class CronSchedule extends Schedule {

    private String expression;

    private ZoneId timezone;

    private transient ExecutionTime executionTime;

    private transient Instant testInstant;

    public CronSchedule(String expression, ZoneId timezone) {
        this.expression = expression;
        this.timezone = timezone;

        this.executionTime = ExecutionTime.forCron(cronParser.parse(this.expression));
        this.testInstant = null;
    }

    public CronSchedule(StreamInput sin) throws IOException {
        this(
                sin.readString(),
                sin.readZoneId()
        );
    }

    public static CronSchedule readFrom(StreamInput sin) throws IOException {
        return new CronSchedule(sin);
    }

    @Override
    public Duration nextTimeToExecute(Instant enabledTime) {
        ZonedDateTime zonedDateTime = ZonedDateTime.ofInstant(testInstant != null? testInstant: Instant.now(), timezone);
        Optional<Duration> timeToNextExecution = executionTime.timeToNextExecution(zonedDateTime);
        return timeToNextExecution.orElse(null);
    }

    @Override
    public Instant getExpectedNextExecutionTime(Instant enabledTime, Instant expectedPreviousExecutionTime) {
        ZonedDateTime zonedDateTime = ZonedDateTime.ofInstant(expectedPreviousExecutionTime != null? expectedPreviousExecutionTime: (testInstant != null? testInstant: Instant.now()), timezone);
        Optional<ZonedDateTime> nextExecution = executionTime.nextExecution(zonedDateTime);
        return nextExecution.map(ChronoZonedDateTime::toInstant).orElse(null);
    }

    @Override
    public Pair<Instant, Instant> getPeriodStartingAt(Instant startTime) {
        Instant realStartTime;
        if (startTime != null) {
            realStartTime = startTime;
        } else {
            Optional<ZonedDateTime> lastExecutionTime = executionTime.lastExecution(ZonedDateTime.now(timezone));
            if (lastExecutionTime.isEmpty()) {
                Instant currentTime = Instant.now();
                return Pair.of(currentTime, currentTime);
            }
            realStartTime = lastExecutionTime.get().toInstant();
        }

        ZonedDateTime zonedDateTime = ZonedDateTime.ofInstant(realStartTime, timezone);
        ZonedDateTime newEndTime = executionTime.nextExecution(zonedDateTime).orElse(null);
        return Pair.of(realStartTime, newEndTime != null? newEndTime.toInstant(): realStartTime);
    }

    @Override
    public Pair<Instant, Instant> getPeriodEndingAt(Instant endTime) {
        Instant realEndTime;
        if (endTime != null) {
            realEndTime = endTime;
        } else {
            Optional<ZonedDateTime> lastExecutionTime = executionTime.lastExecution(ZonedDateTime.now(timezone));
            if (lastExecutionTime.isEmpty()) {
                Instant currentTime = Instant.now();
                return Pair.of(currentTime, currentTime);
            }
            realEndTime = lastExecutionTime.get().toInstant();
        }

        ZonedDateTime zonedDateTime = ZonedDateTime.ofInstant(realEndTime, timezone);
        ZonedDateTime newStartTime = executionTime.nextExecution(zonedDateTime).orElse(null);
        return Pair.of(newStartTime != null? newStartTime.toInstant(): realEndTime, realEndTime);
    }

    @Override
    public Boolean runningOnTime(Instant lastExecutionTime) {
        if (lastExecutionTime == null) {
            return true;
        }
        ZonedDateTime zonedDateTime = ZonedDateTime.ofInstant(testInstant != null? testInstant: Instant.now(), timezone);
        Optional<ZonedDateTime> expectedExecutionTime = executionTime.lastExecution(zonedDateTime);

        if (expectedExecutionTime.isEmpty()) {
            // At this point we know lastExecutionTime is not null, this should never happen.
            // If expected execution time is null, we shouldn't have executed the ScheduledJob.
            return false;
        }
        ZonedDateTime actualExecutionTime = ZonedDateTime.ofInstant(lastExecutionTime, timezone);
        return ChronoUnit.SECONDS.between(expectedExecutionTime.get(), actualExecutionTime) == 0L;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(expression);
        out.writeZoneId(timezone);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject()
                .startObject(CRON_FIELD)
                .field(EXPRESSION_FIELD, expression)
                .field(TIMEZONE_FIELD, timezone.getId())
                .endObject()
                .endObject();
        return builder;
    }
}