/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.model;

import com.cronutils.model.CronType;
import com.cronutils.model.definition.CronDefinitionBuilder;
import com.cronutils.parser.CronParser;
import org.apache.commons.lang3.tuple.Pair;
import org.opensearch.common.io.stream.StreamInput;
import org.opensearch.common.io.stream.Writeable;
import org.opensearch.common.xcontent.ToXContentObject;
import org.opensearch.common.xcontent.XContentParser;
import org.opensearch.common.xcontent.XContentParserUtils;

import java.io.IOException;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Locale;
import java.util.Objects;

abstract class Schedule implements Writeable, ToXContentObject {

    protected static final String CRON_FIELD = "cron";
    protected static final String EXPRESSION_FIELD = "expression";
    protected static final String TIMEZONE_FIELD = "timezone";
    protected static final String PERIOD_FIELD = "period";
    protected static final String INTERVAL_FIELD = "interval";
    protected static final String UNIT_FIELD = "unit";

    protected static final CronParser cronParser = new CronParser(CronDefinitionBuilder.instanceDefinitionFor(CronType.UNIX));

    enum TYPE {
        CRON,
        INTERVAL;

        String getType() throws IOException {
            switch (this) {
                case CRON:
                    return "cron";
                case INTERVAL:
                    return "interval";
                default:
                    throw new IOException(String.format(Locale.getDefault(), "Schedule Type %s not found", this.name()));
            }
        }
    }

    public static Schedule parse(XContentParser xcp) throws IOException {
        String expression = null;
        ZoneId timezone = null;
        Integer interval = null;
        ChronoUnit unit = null;
        Schedule schedule = null;
        TYPE type = null;

        XContentParserUtils.ensureExpectedToken(XContentParser.Token.START_OBJECT, xcp.currentToken(), xcp);
        while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldname = xcp.currentName();
            xcp.nextToken();

            if (type != null) {
                throw new IllegalArgumentException("You can only specify one type of schedule.");
            }

            switch (fieldname) {
                case CRON_FIELD:
                    type = TYPE.CRON;
                    while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
                        String cronFieldName = xcp.currentName();
                        xcp.nextToken();

                        switch (cronFieldName) {
                            case EXPRESSION_FIELD:
                                expression = xcp.textOrNull();
                                break;
                            case TIMEZONE_FIELD:
                                timezone = getTimeZone(xcp.text());
                        }
                    }
                    break;
                case PERIOD_FIELD:
                    type = TYPE.INTERVAL;
                    while (xcp.nextToken() != XContentParser.Token.END_OBJECT) {
                        String cronFieldName = xcp.currentName();
                        xcp.nextToken();

                        switch (cronFieldName) {
                            case INTERVAL_FIELD:
                                interval = xcp.intValue();
                                break;
                            case UNIT_FIELD:
                                unit = ChronoUnit.valueOf(xcp.text().toUpperCase(Locale.getDefault()));
                        }
                    }
                    break;
                default:
                    throw new IllegalArgumentException(String.format(Locale.getDefault(), "Invalid field: %s found in schedule.", fieldname));
            }
        }

        if (type == TYPE.CRON) {
            schedule = new CronSchedule(Objects.requireNonNull(expression, "Expression in cron schedule is null."), Objects.requireNonNull(timezone, "Timezone in cron schedule is null."));
        } else if (type == TYPE.INTERVAL) {
            schedule = new IntervalSchedule(Objects.requireNonNull(interval, "Interval in period schedule is null."), Objects.requireNonNull(unit, "Unit in period schedule is null."));
        }

        return Objects.requireNonNull(schedule, "Schedule is null.");
    }

    private static ZoneId getTimeZone(String timeZone) {
        try {
            return ZoneId.of(timeZone);
        } catch (DateTimeException ex) {
            throw new IllegalArgumentException(String.format(Locale.getDefault(), "Timezone %s is not supported", timeZone));
        }
    }

    public static Schedule readFrom(StreamInput sin) throws IOException {
        TYPE type = sin.readEnum(TYPE.class);
        if (type == TYPE.CRON) {
            return new CronSchedule(sin);
        } else {
            return new IntervalSchedule(sin);
        }
    }

    public abstract Duration nextTimeToExecute(Instant enabledTime);

    public abstract Instant getExpectedNextExecutionTime(Instant enabledTime, Instant expectedPreviousExecutionTime);

    public abstract Pair<Instant, Instant> getPeriodStartingAt(Instant startTime);

    public abstract Pair<Instant, Instant> getPeriodEndingAt(Instant endTime);

    public abstract Boolean runningOnTime(Instant lastExecutionTime);
}