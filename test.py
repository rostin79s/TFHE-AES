def linear_transformation(x):
    # XOR operation is used for addition since each variable is a bit

    # Top linear transformation
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
    
    print("y1:", y1)
    print("y2:", y2)
    print("y3:", y3)
    print("y4:", y4)
    print("y5:", y5)
    print("y6:", y6)
    print("y7:", y7)
    print("y8:", y8)
    print("y9:", y9)
    print("y10:", y10)
    print("y11:", y11)
    print("y12:", y12)
    print("y13:", y13)
    print("y14:", y14)
    print("y15:", y15)
    print("y16:", y16)
    print("y17:", y17)
    print("y18:", y18)
    print("y19:", y19)
    print("y20:", y20)
    print("y21:", y21)


    # Middle non-linear section
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
    

    print(f"t2 = {t2}")
    print(f"t3 = {t3}")
    print(f"t4 = {t4}")
    print(f"t5 = {t5}")
    print(f"t6 = {t6}")
    print(f"t7 = {t7}")
    print(f"t8 = {t8}")
    print(f"t9 = {t9}")
    print(f"t10 = {t10}")
    print(f"t11 = {t11}")
    print(f"t12 = {t12}")
    print(f"t13 = {t13}")
    print(f"t14 = {t14}")
    print(f"t15 = {t15}")
    print(f"t21 = {t21}")
    print(f"t22 = {t22}")
    print(f"t23 = {t23}")
    print(f"t24 = {t24}")
    print(f"t25 = {t25}")
    print(f"t26 = {t26}")
    print(f"t27 = {t27}")
    print(f"t28 = {t28}")
    print(f"t29 = {t29}")
    print(f"t30 = {t30}")
    print(f"t31 = {t31}")
    print(f"t32 = {t32}")
    print(f"t33 = {t33}")
    print(f"t34 = {t34}")
    print(f"t35 = {t35}")
    print(f"t36 = {t36}")
    print(f"t37 = {t37}")
    print(f"t38 = {t38}")
    print(f"t39 = {t39}")
    print(f"t40 = {t40}")
    print(f"t41 = {t41}")
    print(f"t42 = {t42}")
    print(f"t43 = {t43}")
    print(f"t44 = {t44}")
    print(f"t45 = {t45}")
    

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
    
    
    print(f"z0 = {z0}")
    print(f"z1 = {z1}")
    print(f"z2 = {z2}")
    print(f"z3 = {z3}")
    print(f"z4 = {z4}")
    print(f"z5 = {z5}")
    print(f"z6 = {z6}")
    print(f"z7 = {z7}")
    print(f"z8 = {z8}")
    print(f"z9 = {z9}")
    print(f"z10 = {z10}")
    print(f"z11 = {z11}")
    print(f"z12 = {z12}")
    print(f"z13 = {z13}")
    print(f"z14 = {z14}")
    print(f"z15 = {z15}")
    print(f"z16 = {z16}")
    print(f"z17 = {z17}")
    
    # z = [
    #     t44 & y15, t37 & y6, t33 & x[7], t43 & y16,
    #     t40 & y1, t29 & y7, t42 & y11, t45 & y17,
    #     t41 & y10, t44 & y12, t37 & y3, t33 & y4,
    #     t43 & y13, t40 & y5, t29 & y2, t42 & y9,
    #     t45 & y14, t41 & y8
    # ]

    t46 = z15 ^ z16
    t47 = z10 ^ z11
    t48 = z5 ^ z13
    t49 = z9 ^ z10
    t50 = z2 ^ z12
    t51 = z2 ^ z5
    t52 = z7 ^ z8
    t53 = z0 ^ z3
    t54 = z6 ^ z7
    t55 = z16 ^ z17
    t56 = z12 ^ t48
    t57 = t50 ^ t53
    t58 = z4 ^ t46
    t59 = z3 ^ t54
    t60 = t46 ^ t57
    t61 = z14 ^ t57
    t62 = t52 ^ t58
    t63 = t49 ^ t58
    t64 = z4 ^ t59
    t65 = t61 ^ t62
    t66 = z1 ^ t63
    s0 = t59 ^ t63
    s6 = 1 - (t56 ^ t62)  # XNOR is the negation of XOR
    s7 = 1 - (t48 ^ t60)
    t67 = t64 ^ t65
    s3 = t53 ^ t66
    s4 = t51 ^ t66
    s5 = t47 ^ t65
    s1 = 1 - (t64 ^ s3)
    s2 = 1 - (t55 ^ t67)

    # Outputs
    return [s0, s1, s2, s3, s4, s5, s6, s7]

# Example usage with 8-bit input
x = [1,1,0,0,0,0,0,0]  # Replace with actual bit inputs
result = linear_transformation(x)
print("Result:", result)