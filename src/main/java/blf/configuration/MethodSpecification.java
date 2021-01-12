package blf.configuration;

import java.util.Arrays;
import java.util.List;

import blf.core.interfaces.Method;
import blf.library.Library;

/**
 * MethodSpecification
 */
public class MethodSpecification {
    private final Method method;

    private MethodSpecification(Method method) {
        this.method = method;
    }

    Method getMethod() {
        return this.method;
    }

    public static MethodSpecification of(Method method) {
        return new MethodSpecification(method);
    }

    public static MethodSpecification of(String name, String... parameterTypes) throws BuildException {
        return of(name, Arrays.asList(parameterTypes));
    }

    public static MethodSpecification of(String name, List<String> parameterTypes) throws BuildException {
        final Method method = Library.INSTANCE.findMethod(name, parameterTypes);
        if (method == null) {
            final String message = String.format("%s(%s)", name, String.join(",", parameterTypes));
            throw new BuildException(message);
        }
        return new MethodSpecification(method);
    }

}
