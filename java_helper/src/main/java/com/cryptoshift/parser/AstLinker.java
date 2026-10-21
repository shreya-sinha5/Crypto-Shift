package com.cryptoshift.parser;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.Node;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;

/**
 * AST Linker — Maps file/line references from a CBOM to JavaParser AST nodes.
 *
 * <p>Given a Java source file and a line number, returns:
 * <ul>
 *   <li>AST node type and descriptor (e.g., MethodCallExpr:KeyPairGenerator.getInstance)</li>
 *   <li>Enclosing method name</li>
 *   <li>Enclosing class name</li>
 * </ul>
 *
 * <p>Invoked by the Python CLI as a subprocess: reads JSON from stdin, writes JSON to stdout.
 *
 * <p>Input JSON:
 * <pre>{"file": "path/to/File.java", "line": 42}</pre>
 *
 * <p>Output JSON:
 * <pre>{
 *   "file": "path/to/File.java",
 *   "line": 42,
 *   "ast_node": "MethodCallExpr:KeyPairGenerator.getInstance",
 *   "enclosing_method": "generateKeyPair",
 *   "enclosing_class": "KeyService",
 *   "linked": true
 * }</pre>
 */
public class AstLinker {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Link a file/line reference to an AST node.
     *
     * @param filePath Path to the Java source file
     * @param line     Line number (1-indexed)
     * @return JSON object with linking result
     */
    public static ObjectNode linkToAst(String filePath, int line) throws IOException {
        ObjectNode result = MAPPER.createObjectNode();
        result.put("file", filePath);
        result.put("line", line);

        File sourceFile = new File(filePath);
        if (!sourceFile.exists()) {
            result.put("linked", false);
            result.put("reason", "file_not_found");
            return result;
        }

        try {
            CompilationUnit cu = StaticJavaParser.parse(sourceFile);

            // Find the AST node at the specified line
            Optional<Node> nodeAtLine = cu.findAll(Node.class).stream()
                    .filter(n -> n.getBegin().isPresent() && n.getBegin().get().line == line)
                    .findFirst();

            if (nodeAtLine.isEmpty()) {
                result.put("linked", false);
                result.put("reason", "no_node_at_line");
                return result;
            }

            Node node = nodeAtLine.get();

            // Determine node descriptor
            String nodeType = node.getClass().getSimpleName();
            String descriptor = nodeType;
            if (node instanceof MethodCallExpr mce) {
                descriptor = nodeType + ":" + mce.getNameAsString();
                mce.getScope().ifPresent(scope ->
                        result.put("scope", scope.toString()));
            }

            result.put("ast_node", descriptor);
            result.put("node_type", nodeType);

            // Find enclosing method
            Optional<MethodDeclaration> enclosingMethod = node.findAncestor(MethodDeclaration.class);
            enclosingMethod.ifPresent(m -> result.put("enclosing_method", m.getNameAsString()));

            // Find enclosing class
            Optional<ClassOrInterfaceDeclaration> enclosingClass =
                    node.findAncestor(ClassOrInterfaceDeclaration.class);
            enclosingClass.ifPresent(c -> result.put("enclosing_class", c.getNameAsString()));

            result.put("linked", true);

        } catch (Exception e) {
            result.put("linked", false);
            result.put("reason", "parse_error");
            result.put("error", e.getMessage());
        }

        return result;
    }

    /**
     * Batch link multiple file/line references.
     *
     * @param inputJson JSON array of {file, line} objects
     * @return JSON array of linking results
     */
    public static ArrayNode batchLink(String inputJson) throws IOException {
        ArrayNode input = (ArrayNode) MAPPER.readTree(inputJson);
        ArrayNode results = MAPPER.createArrayNode();

        for (var entry : input) {
            String file = entry.get("file").asText();
            int line = entry.get("line").asInt();
            results.add(linkToAst(file, line));
        }

        return results;
    }

    /**
     * CLI entry point. Reads JSON from stdin, writes results to stdout.
     */
    public static void main(String[] args) throws IOException {
        String input;

        if (args.length >= 2) {
            // Direct invocation: java AstLinker <file> <line>
            ObjectNode result = linkToAst(args[0], Integer.parseInt(args[1]));
            System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(result));
        } else {
            // Stdin mode: read JSON array
            input = new String(System.in.readAllBytes());
            ArrayNode results = batchLink(input);
            System.out.println(MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(results));
        }
    }
}
