/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.types;

public class SigmaBool implements SigmaType {

    private boolean aBoolean;

    public SigmaBool(boolean aBoolean) {
        this.aBoolean = aBoolean;
    }
}