from dataclasses import dataclass
from typing import Dict, List, Set, Tuple
import re

@dataclass
class Operation:
    target: str
    op_type: str  # 'xor' or 'and'
    operands: List[str]
    line: str

class TFHEOptimizer:
    def __init__(self):
        self.operations: List[Operation] = []
        self.bit_counts: Dict[str, int] = {}  # Tracks accumulated bits for each variable
        self.bootstrap_points: Set[str] = set()  # Variables that need bootstrapping
        self.dependencies: Dict[str, Set[str]] = {}  # Tracks variable dependencies
        
    def parse_operations(self, code: str):
        """Parse the operations from the code."""
        lines = [line.strip() for line in code.split('\n') if '=' in line]
        
        for line in lines:
            if '^' in line:  # XOR operation
                target, expr = line.split('=')
                target = target.strip()
                operands = [op.strip() for op in expr.split('^')]
                self.operations.append(Operation(target, 'xor', operands, line))
            elif '&' in line:  # AND operation
                target, expr = line.split('=')
                target = target.strip()
                operands = [op.strip() for op in expr.split('&')]
                self.operations.append(Operation(target, 'and', operands, line))
                
    def initialize_input_bits(self, inputs: List[str]):
        """Initialize input variables with bit count 1."""
        for var in inputs:
            self.bit_counts[var] = 1
            
    def check_and_constraints(self, op1_bits: int, op2_bits: int) -> bool:
        """Check if AND operation is possible given the bit counts."""
        return (op1_bits < 4 and op2_bits < 4) or \
               (op1_bits < 8 and op2_bits < 2) or \
               (op1_bits < 2 and op2_bits < 8)
                
    def optimize(self):
        """Find optimal bootstrapping points."""
        # Initialize all variables with their starting bit counts
        for op in self.operations:
            if op.target not in self.bit_counts:
                self.bit_counts[op.target] = 0
                
        # Process operations in order
        for op in self.operations:
            if op.op_type == 'xor':
                # Calculate accumulated bits
                total_bits = sum(self.bit_counts.get(operand, 1) for operand in op.operands)
                
                # Check if bootstrapping is needed
                if total_bits > 15:
                    # Find the operand with the most bits to bootstrap
                    max_bits_operand = max(op.operands, key=lambda x: self.bit_counts.get(x, 1))
                    self.bootstrap_points.add(max_bits_operand)
                    self.bit_counts[max_bits_operand] = 1
                    
                # Update bit count for target
                self.bit_counts[op.target] = sum(self.bit_counts.get(operand, 1) for operand in op.operands)
                
            elif op.op_type == 'and':
                # AND operations always need bootstrapping of operands if they don't meet constraints
                op1, op2 = op.operands
                if not self.check_and_constraints(self.bit_counts.get(op1, 1), self.bit_counts.get(op2, 1)):
                    self.bootstrap_points.add(op1)
                    self.bootstrap_points.add(op2)
                    self.bit_counts[op1] = 1
                    self.bit_counts[op2] = 1
                
                # AND result is always 1 bit
                self.bit_counts[op.target] = 1
                
    def print_optimization_result(self):
        """Print the optimization results."""
        print(f"Total bootstrap operations needed: {len(self.bootstrap_points)}")
        print("\nBootstrap points:")
        for var in sorted(self.bootstrap_points):
            print(f"- {var}")
            
        print("\nFinal bit counts:")
        for var, bits in sorted(self.bit_counts.items()):
            print(f"{var}: {bits} bits")

# Example usage
def main():
    # Extract input variables (x[0] through x[7])
    inputs = [f"x[{i}]" for i in range(8)]
    
    # Create optimizer
    optimizer = TFHEOptimizer()
    
    # Initialize input variables
    optimizer.initialize_input_bits(inputs)
    
    # Parse the operations from your code
    code = """
    # Your operations here
    y14 = x[3] ^ x[5]
    y13 = x[0] ^ x[6]
    y9 = x[0] ^ x[3]
    y8 = x[0] ^ x[5]
    t0 = x[1] ^ x[2]
    y1 = t0 ^ x[7]
    y4 = y1 ^ x[3]
    y12 = y13 ^ y14
    y2 = y1 ^ x[0]
    y5 = y1 ^ x[6]
    y3 = y5 ^ y8
    t1 = x[4] ^ y12
    y15 = t1 ^ x[5]
    y20 = t1 ^ x[1]
    y6 = y15 ^ x[7]
    y10 = y15 ^ t0
    y11 = y20 ^ y9
    y7 = x[7] ^ y11
    y17 = y10 ^ y11
    y19 = y10 ^ y8
    y16 = t0 ^ y11
    y21 = y13 ^ y16
    y18 = x[0] ^ y16

    t2 = y12 & y15
    t3 = y3 & y6
    t4 = t3 ^ t2
    t5 = y4 & x[7]
    t6 = t5 ^ t2
    t7 = y13 & y16
    t8 = y5 & y1
    t9 = t8 ^ t7
    t10 = y2 & y7
    t11 = t10 ^ t7
    t12 = y9 & y11
    t13 = y14 & y17
    t14 = t13 ^ t12
    t15 = y8 & y10
    t16 = t15 ^ t12
    t17 = t4 ^ t14
    t18 = t6 ^ t16
    t19 = t9 ^ t14
    t20 = t11 ^ t16
    t21 = t17 ^ y20
    t22 = t18 ^ y19
    t23 = t19 ^ y21
    t24 = t20 ^ y18
    t25 = t21 ^ t22
    t26 = t21 & t23
    t27 = t24 ^ t26
    t28 = t25 & t27
    t29 = t28 ^ t22
    t30 = t23 ^ t24
    t31 = t22 ^ t26
    t32 = t31 & t30
    t33 = t32 ^ t24
    t34 = t23 ^ t33
    t35 = t27 ^ t33
    t36 = t24 & t35
    t37 = t36 ^ t34
    t38 = t27 ^ t36
    t39 = t29 & t38
    t40 = t25 ^ t39
    t41 = t40 ^ t37
    t42 = t29 ^ t33
    t43 = t29 ^ t40
    t44 = t33 ^ t37
    t45 = t42 ^ t41
    
    z0 = t44 & y15
    z1 = t37 & y6
    z2 = t33 & x[7]
    z3 = t43 & y16
    z4 = t40 & y1
    z5 = t29 & y7
    z6 = t42 & y11
    z7 = t45 & y17
    z8 = t41 & y10
    z9 = t44 & y12
    z10 = t37 & y3
    z11 = t33 & y4
    z12 = t43 & y13
    z13 = t40 & y5
    z14 = t29 & y2
    z15 = t42 & y9
    z16 = t45 & y14
    z17 = t41 & y8
    # ... rest of your operations ...
    """
    
    optimizer.parse_operations(code)
    optimizer.optimize()
    optimizer.print_optimization_result()

if __name__ == "__main__":
    main()