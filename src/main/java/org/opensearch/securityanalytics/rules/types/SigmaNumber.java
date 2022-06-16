/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.types;

public class SigmaNumber implements SigmaType {

    private Integer numOpt1;

    private Float numOpt2;

    public SigmaNumber(int numOpt1) {
        this.numOpt1 = numOpt1;
    }

    public SigmaNumber(float numOpt2) {
        this.numOpt2 = numOpt2;
    }

    @Override
    public String toString() {
        return numOpt1 != null? String.valueOf(numOpt1): String.valueOf(numOpt2);
    }
}