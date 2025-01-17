use super::*;

fn and(l: &Ciphertext, r: &Ciphertext, shift: u8, lut: &LookupTable<Vec<u64>>, sks: &ServerKey, cks: &ClientKey) -> Ciphertext {
    // let g = |x: u64| x%2;
    // let lut2 = sks.generate_lookup_table(&g);
    // let l = bootstrap(l, &lut2, &sks);

    let t = sks.unchecked_scalar_mul(&l, shift);
    // println!("T1: {}", cks.decrypt(&t));
    let t = sks.unchecked_add(&t, &r);
    // println!("T2: {}", cks.decrypt(&t));
    let t = sks.apply_lookup_table(&t, &lut);
    return t;
}

fn bootstrap(ct: &Ciphertext, lut: &LookupTable<Vec<u64>>, sks: &ServerKey) -> Ciphertext{
    return sks.apply_lookup_table(&ct, &lut);
}


pub fn sbox(cks: &ClientKey, sks: &ServerKey, x: &mut [Ciphertext]) {

    let start = std::time::Instant::now();

    let x0: &Ciphertext = &x[0];
    let x1: &Ciphertext = &x[1];
    let x2: &Ciphertext = &x[2];
    let x3: &Ciphertext = &x[3];
    let x4: &Ciphertext = &x[4];
    let x5: &Ciphertext = &x[5];
    let x6: &Ciphertext = &x[6];
    let x7: &Ciphertext = &x[7];

    let f = |x: u64| (((x/8)%2) & (x%2) )%2;
    let lut = sks.generate_lookup_table(&f);

    let g = |x: u64| x%2;
    let lut2 = sks.generate_lookup_table(&g);



    // Perform the linear transformations

    let x7 = bootstrap(&x7, &lut2, &sks);

    let y14 = sks.unchecked_add(&x3, &x5);
    let y14 = bootstrap(&y14, &lut2, &sks);

    let y13 = sks.unchecked_add(&x0, &x6);
    let y13 = bootstrap(&y13, &lut2, &sks);

    let y9 = sks.unchecked_add(&x0, &x3);
    let y9 = bootstrap(&y9, &lut2, &sks);

    let y8 = sks.unchecked_add(&x0, &x5);
    let y8 = bootstrap(&y8, &lut2, &sks);

    let t0 = sks.unchecked_add(&x1, &x2);
    let t0 = bootstrap(&t0, &lut2, &sks);

    let y1 = sks.unchecked_add(&t0, &x7); // 2

    let y4 = sks.unchecked_add(&y1, &x3);
    let y4 = bootstrap(&y4, &lut2, &sks);

    let y12 = sks.unchecked_add(&y13, &y14); // 2

    let y2 = sks.unchecked_add(&y1, &x0);
    let y2 = bootstrap(&y2, &lut2, &sks);

    let y5 = sks.unchecked_add(&y1, &x6);
    let y5 = bootstrap(&y5, &lut2, &sks);

    let y3 = sks.unchecked_add(&y5, &y8); // 2

    let t1 = sks.unchecked_add(&x4, &y12);
    let y15 = sks.unchecked_add(&t1, &x5);
    let y15 = bootstrap(&y15, &lut2, &sks);

    let y20 = sks.unchecked_add(&t1, &x1);

    let y6 = sks.unchecked_add(&y15, &x7); // 2

    let y10 = sks.unchecked_add(&y15, &t0); // 2

    let y11 = sks.unchecked_add(&y20, &y9); // 2

    let y7 = sks.unchecked_add(&x7, &y11); // 3


    let y17 = sks.unchecked_add(&y10, &y11); // 3
    let y19 = sks.unchecked_add(&y10, &y8); // 2

    let y16 = sks.unchecked_add(&t0, &y11); // 3

    let y21 = sks.unchecked_add(&y13, &y16); // 2

    let y18 = sks.unchecked_add(&x0, &y16);
    let y18 = bootstrap(&y18, &lut2, &sks);

    

    // println!("Y Ciphertexts:");
    // println!("y1 {}", cks.decrypt(&y1));
    // println!("y2 {}", cks.decrypt(&y2));
    // println!("y3 {}", cks.decrypt(&y3));
    // println!("y4 {}", cks.decrypt(&y4));
    // println!("y5 {}", cks.decrypt(&y5));
    // println!("y6 {}", cks.decrypt(&y6));
    // println!("y7 {}", cks.decrypt(&y7));
    // println!("y8 {}", cks.decrypt(&y8));
    // println!("y9 {}", cks.decrypt(&y9));
    // println!("y10 {}", cks.decrypt(&y10));
    // println!("y11 {}", cks.decrypt(&y11));
    // println!("y12 {}", cks.decrypt(&y12));
    // println!("y13 {}", cks.decrypt(&y13));
    // println!("y14 {}", cks.decrypt(&y14));
    // println!("y15 {}", cks.decrypt(&y15));
    // println!("y16 {}", cks.decrypt(&y16));
    // println!("y17 {}", cks.decrypt(&y17));
    // println!("y18 {}", cks.decrypt(&y18));
    // println!("y19 {}", cks.decrypt(&y19));
    // println!("y20 {}", cks.decrypt(&y20));
    // println!("y21 {}", cks.decrypt(&y21));


    // middle non-linear layer
    

   
    let t2 = and(&y12, &y15, 8, &lut, &sks, &cks); // 1
    let t3 = and(&y3, &y6, 8, &lut, &sks, &cks); // 1
    let t4 = sks.unchecked_add(&t3, &t2); // 2
    let t5 = and(&y4,&x7, 8, &lut, &sks, &cks); // 1
    let t6 = sks.unchecked_add(&t5, &t2); // 2

    
    let t7 = and(&y13,&y16, 8, &lut, &sks, &cks); // 1
    let t8 = and(&y5,&y1, 8, &lut, &sks, &cks); // 1
    let t9 = sks.unchecked_add(&t8, &t7); // 2
    let t10 = and(&y2,&y7, 8, &lut, &sks, &cks); // 1
    let t11 = sks.unchecked_add(&t10, &t7); // 2
    let t12 = and(&y9,&y11, 8, &lut, &sks, &cks); // 1
    let t13 = and(&y14,&y17, 8, &lut, &sks, &cks); // 1
    let t14 = sks.unchecked_add(&t13, &t12); // 2


  
    let t15 = and(&y8,&y10, 8, &lut, &sks, &cks); // 1
    let t16 = sks.unchecked_add(&t15, &t12); // 2
    let t17 = sks.unchecked_add(&t4, &t14); // 4
    let t18 = sks.unchecked_add(&t6, &t16); // 4
    let t19 = sks.unchecked_add(&t9, &t14); // 4
    let t20 = sks.unchecked_add(&t11, &t16); // 4

    let t21 = sks.unchecked_add(&t17, &y20); // 16+
    let t21 = bootstrap(&t21, &lut2, &sks);

    let t22 = sks.unchecked_add(&t18, &y19); // 6 
    let t22 = bootstrap(&t22, &lut2, &sks);

    let t23 = sks.unchecked_add(&t19, &y21); // 6 
    let t23 = bootstrap(&t23, &lut2, &sks);

    let t24 = sks.unchecked_add(&t20, &y18); // 5
    let t24 = bootstrap(&t24, &lut2, &sks);

    let t25 = sks.unchecked_add(&t21, &t22); // 2

    
    let t26 = and(&t21,&t23, 8, &lut, &sks, &cks); // 1

    let t27 = sks.unchecked_add(&t24, &t26); // 2

    let t28 = and(&t25, &t27, 8, &lut, &sks, &cks); // 1

    let t29 = sks.unchecked_add(&t28, &t22); // 2
    let t30 = sks.unchecked_add(&t23, &t24); // 2
    let t31 = sks.unchecked_add(&t22, &t26); // 2

    let t32 = and(&t30, &t31, 8, &lut, &sks, &cks); // 1
    
    let t33 = sks.unchecked_add(&t32, &t24); // 2
    let t34 = sks.unchecked_add(&t23, &t33); // 3
    let t35 = sks.unchecked_add(&t27, &t33); // 4

    let t36 = and(&t24, &t35, 8, &lut, &sks, &cks); // 1

    let t37 = sks.unchecked_add(&t36, &t34); // 4
    let t38 = sks.unchecked_add(&t27, &t36); // 3

    let t39 = and(&t38, &t29, 8, &lut, &sks, &cks); // 1


    let t40 = sks.unchecked_add(&t25, &t39); // 3

    let t41 = sks.unchecked_add(&t40, &t37); // 8
    let t41 = bootstrap(&t41, &lut2, &sks);

    let t42 = sks.unchecked_add(&t29, &t33); // 4
    let t43 = sks.unchecked_add(&t29, &t40); // 5
    let t44 = sks.unchecked_add(&t33, &t37); // 6
    let t45 = sks.unchecked_add(&t42, &t41); // 5


    // let t40 = bootstrap(&t40, &lut2, &sks);
    // let t41 = bootstrap(&t41, &lut2, &sks);
    // let t42 = bootstrap(&t42, &lut2, &sks);
    // let t43 = bootstrap(&t43, &lut2, &sks);
    // let t44 = bootstrap(&t44, &lut2, &sks);
    // let t45 = bootstrap(&t45, &lut2, &sks);

    // println!("T Ciphertexts:");
    // println!("t2 {}", cks.decrypt(&t2));
    // println!("t3 {}", cks.decrypt(&t3));
    // println!("t4 {}", cks.decrypt(&t4));
    // println!("t5 {}", cks.decrypt(&t5));
    // println!("t6 {}", cks.decrypt(&t6));
    // println!("t7 {}", cks.decrypt(&t7));
    // println!("t8 {}", cks.decrypt(&t8));
    // println!("t9 {}", cks.decrypt(&t9));
    // println!("t10 {}", cks.decrypt(&t10));
    // println!("t11 {}", cks.decrypt(&t11));
    // println!("t12 {}", cks.decrypt(&t12));
    // println!("t13 {}", cks.decrypt(&t13));
    // println!("t14 {}", cks.decrypt(&t14));
    // println!("t15 {}", cks.decrypt(&t15));
    // println!("t21 {}", cks.decrypt(&t21));
    // println!("t22 {}", cks.decrypt(&t22));
    // println!("t23 {}", cks.decrypt(&t23));
    // println!("t24 {}", cks.decrypt(&t24));
    // println!("t25 {}", cks.decrypt(&t25));
    // println!("t26 {}", cks.decrypt(&t26));
    // println!("t27 {}", cks.decrypt(&t27));
    // println!("t28 {}", cks.decrypt(&t28));
    // println!("t29 {}", cks.decrypt(&t29));
    // println!("t30 {}", cks.decrypt(&t30));
    // println!("t31 {}", cks.decrypt(&t31));
    // println!("t32 {}", cks.decrypt(&t32));
    // println!("t33 {}", cks.decrypt(&t33));
    // println!("t34 {}", cks.decrypt(&t34));
    // println!("t35 {}", cks.decrypt(&t35));
    // println!("t36 {}", cks.decrypt(&t36));
    // println!("t37 {}", cks.decrypt(&t37));
    // println!("t38 {}", cks.decrypt(&t38));
    // println!("t39 {}", cks.decrypt(&t39));
    // println!("t40 {}", cks.decrypt(&t40));
    // println!("t41 {}", cks.decrypt(&t41));
    // println!("t42 {}", cks.decrypt(&t42));
    // println!("t43 {}", cks.decrypt(&t43));
    // println!("t44 {}", cks.decrypt(&t44));
    // println!("t45 {}", cks.decrypt(&t45));

    let shift = 8;
    
    let z0 = and(&t44, &y15, shift, &lut, &sks, &cks);
    let z1 = and(&t37, &y6, shift, &lut, &sks, &cks);
    let z2 = and(&t33, &x7, shift, &lut, &sks, &cks);
    let z3 = and(&t43, &y16, shift, &lut, &sks, &cks);
    let z4 = and(&t40, &y1, shift, &lut, &sks, &cks);
    let z5 = and(&t29, &y7, shift, &lut, &sks, &cks);
    let z6 = and(&t42, &y11, shift, &lut, &sks, &cks);
    let z7 = and(&t45, &y17, shift, &lut, &sks, &cks);
    let z8 = and(&t41, &y10, shift, &lut, &sks, &cks);
    let z9 = and(&t44, &y12, shift, &lut, &sks, &cks);
    let z10 = and(&t37, &y3, shift, &lut, &sks, &cks);
    let z11 = and(&t33, &y4, shift, &lut, &sks, &cks);
    let z12 = and(&t43, &y13, shift, &lut, &sks, &cks);
    let z13 = and(&t40, &y5, shift, &lut, &sks, &cks);
    let z14 = and(&t29, &y2, shift, &lut, &sks, &cks);
    let z15 = and(&t42, &y9, shift, &lut, &sks, &cks);
    let z16 = and(&t45, &y14, shift, &lut, &sks, &cks);
    let z17 = and(&t41, &y8, shift, &lut, &sks, &cks);


    // println!("Z Ciphertexts:");
    // println!("z0: {}", cks.decrypt(&z0));
    // println!("z1: {}", cks.decrypt(&z1));
    // println!("z2: {}", cks.decrypt(&z2));
    // println!("z3: {}", cks.decrypt(&z3));
    // println!("z4: {}", cks.decrypt(&z4));
    // println!("z5: {}", cks.decrypt(&z5));
    // println!("z6: {}", cks.decrypt(&z6));
    // println!("z7: {}", cks.decrypt(&z7));
    // println!("z8: {}", cks.decrypt(&z8));
    // println!("z9: {}", cks.decrypt(&z9));
    // println!("z10: {}", cks.decrypt(&z10));
    // println!("z11: {}", cks.decrypt(&z11));
    // println!("z12: {}", cks.decrypt(&z12));
    // println!("z13: {}", cks.decrypt(&z13));
    // println!("z14: {}", cks.decrypt(&z14));
    // println!("z15: {}", cks.decrypt(&z15));
    // println!("z16: {}", cks.decrypt(&z16));
    // println!("z17: {}", cks.decrypt(&z17));



    // third linear layer
    
    let t46 = sks.unchecked_add(&z15, &z16);
    let t47 = sks.unchecked_add(&z10, &z11);
    let t48 = sks.unchecked_add(&z5, &z13);
    let t49 = sks.unchecked_add(&z9, &z10);
    let t50 = sks.unchecked_add(&z2, &z12);
    let t51 = sks.unchecked_add(&z2, &z5);
    let t52 = sks.unchecked_add(&z7, &z8);
    let t53 = sks.unchecked_add(&z0, &z3);
    let t54 = sks.unchecked_add(&z6, &z7);
    let t55 = sks.unchecked_add(&z16, &z17);
    let t56 = sks.unchecked_add(&z12, &t48);
    let t57 = sks.unchecked_add(&t50, &t53);
    let t58 = sks.unchecked_add(&z4, &t46);
    let t59 = sks.unchecked_add(&z3, &t54);
    let t60 = sks.unchecked_add(&t46, &t57);
    let t61 = sks.unchecked_add(&z14, &t57);
    let t62 = sks.unchecked_add(&t52, &t58);
    let t63 = sks.unchecked_add(&t49, &t58);
    let t64 = sks.unchecked_add(&z4, &t59);
    let t65 = sks.unchecked_add(&t61, &t62);
    let t66 = sks.unchecked_add(&z1, &t63);

    // println!("T Ciphertexts:");
    // println!("t46: {}", cks.decrypt(&t46));
    // println!("t47: {}", cks.decrypt(&t47));
    // println!("t48: {}", cks.decrypt(&t48));
    // println!("t49: {}", cks.decrypt(&t49));
    // println!("t50: {}", cks.decrypt(&t50));
    // println!("t51: {}", cks.decrypt(&t51));
    // println!("t59: {}", cks.decrypt(&t59));
    // println!("t63: {}", cks.decrypt(&t63));


    let s0 = sks.unchecked_add(&t59, &t63);
    let s6 = sks.unchecked_scalar_add(&sks.unchecked_add(&t56, &t62),1);
    let s7 = sks.unchecked_scalar_add(&sks.unchecked_add(&t48, &t60),1);
    let t67 = sks.unchecked_add(&t64, &t65);
    let s3 = sks.unchecked_add(&t53, &t66);
    let s4 = sks.unchecked_add(&t51, &t66);
    let s5 = sks.unchecked_add(&t47, &t65);
    let s1 = sks.unchecked_scalar_add(&sks.unchecked_add(&t64, &s3),1);
    let s2 = sks.unchecked_scalar_add(&sks.unchecked_add(&t55, &t67),1);

    // let s0 = bootstrap(&s0, &lut2, &sks);
    // let s1 = bootstrap(&s1, &lut2, &sks);
    // let s2 = bootstrap(&s2, &lut2, &sks);
    // let s3 = bootstrap(&s3, &lut2, &sks);
    // let s4 = bootstrap(&s4, &lut2, &sks);
    // let s5 = bootstrap(&s5, &lut2, &sks);
    // let s6 = bootstrap(&s6, &lut2, &sks);
    // let s7 = bootstrap(&s7, &lut2, &sks);
    

    // println!("Decrypted S-Box Results:");
    // println!("s0: {}", cks.decrypt(&s0)%2);
    // println!("s1: {}", cks.decrypt(&s1)%2);
    // println!("s2: {}", cks.decrypt(&s2)%2);
    // println!("s3: {}", cks.decrypt(&s3)%2);
    // println!("s4: {}", cks.decrypt(&s4)%2);
    // println!("s5: {}", cks.decrypt(&s5)%2);
    // println!("s6: {}", cks.decrypt(&s6)%2);
    // println!("s7: {}", cks.decrypt(&s7)%2);
    


    x[0] = s0;
    x[1] = s1;
    x[2] = s2;
    x[3] = s3;
    x[4] = s4;
    x[5] = s5;
    x[6] = s6;
    x[7] = s7;

    let elapsed = start.elapsed();
    println!("Time elapsed: {:?}", elapsed);

}

