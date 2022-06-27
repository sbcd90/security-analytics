/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.exceptions;

public class SigmaConditionError extends SigmaError {

    public SigmaConditionError(String message) {
        super(message);
    }
}