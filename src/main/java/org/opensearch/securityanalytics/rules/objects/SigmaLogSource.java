/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.rules.objects;

import java.util.Map;

public class SigmaLogSource {

    private String product;

    private String category;

    private String service;

    public SigmaLogSource(String product, String category, String service) {
        this.product = product;
        this.category = category;
        this.service = service;
    }

    protected static SigmaLogSource fromDict(Map<String, Object> logSource) {
        String product = "";
        if (logSource.containsKey("product")) {
            product = logSource.get("product").toString();
        }

        String category = "";
        if (logSource.containsKey("category")) {
            category = logSource.get("category").toString();
        }

        String service = "";
        if (logSource.containsKey("service")) {
            service = logSource.get("service").toString();
        }
        return new SigmaLogSource(product, category, service);
    }
}