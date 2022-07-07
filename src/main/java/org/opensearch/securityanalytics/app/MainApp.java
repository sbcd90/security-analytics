/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.opensearch.securityanalytics.app;

import org.opensearch.securityanalytics.rules.backend.OSQueryBackend;
import org.opensearch.securityanalytics.rules.backend.QueryBackend;
import org.opensearch.securityanalytics.rules.exceptions.SigmaError;
import org.opensearch.securityanalytics.rules.objects.SigmaRule;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class MainApp {

    public static void main(String[] args) throws IOException, SigmaError, URISyntaxException {
        MainApp mainApp = new MainApp();
        final String url = Objects.requireNonNull(mainApp.getClass().getClassLoader().getResource("rules/")).toURI().toString();
        Path path;
        if (url.contains("!")) {
            final Map<String, String> env = new HashMap<>();
            final String[] array = url.split("!");
            final FileSystem fs = FileSystems.newFileSystem(URI.create(array[0]), env);
            path = fs.getPath(array[1]);
        } else {
            path = Path.of(Objects.requireNonNull(mainApp.getClass().getClassLoader().getResource("rules/")).toURI());
        }

        Stream<Path> folder = Files.list(path);

        List<String> rules = mainApp.getRules(folder.collect(Collectors.toList()));

        for (String ruleStr: rules) {
//           if (ruleStr.contains("SQL Injection Strings")) {
//                System.out.println(ruleStr);
                SigmaRule rule = SigmaRule.fromYaml(ruleStr, true);

                QueryBackend backend = new OSQueryBackend(true, false);
                List<Object> queries = backend.convertRule(rule);
                System.out.println(queries.get(0).toString());
//            }
        }
    }

    private List<String> getRules(List<Path> listOfRules) {
        List<String> rules = new ArrayList<>();

        listOfRules.forEach(new Consumer<Path>() {
            @Override
            public void accept(Path path) {
                try {
                    if (Files.isDirectory(path)) {
                        rules.addAll(getRules(Files.list(path).collect(Collectors.toList())));
                    } else {
                        rules.add(Files.readString(path, Charset.defaultCharset()));
                    }
                } catch (IOException ex) {
                    // suppress with log
//                   System.out.println("rules cannot be parsed");
                }
            }
        });
        return rules;
    }
}