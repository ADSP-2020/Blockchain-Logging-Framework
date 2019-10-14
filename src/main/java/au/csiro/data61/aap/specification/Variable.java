package au.csiro.data61.aap.specification;

import java.util.Objects;

import au.csiro.data61.aap.specification.types.SolidityType;

/**
 * Variable
 */
public class Variable extends ValueContainer {
    
    public Variable(SolidityType<?> type, String name) {
       super(type, name);
    }

    public void setValue(Object value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return String.format("%s %s", this.getType(), this.getName());
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof Variable)) {
            return false;
        }

        if (obj == this) {
            return true;
        }

        final Variable v = (Variable)obj;
        return v.getName().equals(this.getName()) && v.getType().equals(this.getType());
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.getType(), this.getName(), Variable.class);
    }
    
}