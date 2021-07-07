#include "EncryptedQueryProcessing.h"


Ciphertext sum(size_t dimension, double scale, Ciphertext ct, GaloisKeys galk)
{
    // Setting up encryption parameters
    EncryptionParameters parms(scheme_type::CKKS);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 30, 60 })); //This time result will be big, so use 60
                                                                                        //so we have 30 bit room for integer output

    // Set up the SEALContext
    auto context = SEALContext::Create(parms);

    cout << "SERVER : Parameters are valid: " << boolalpha
        << context->key_context_data()->qualifiers().parameters_set << endl;
    cout << "SERVER : Maximal allowed coeff_modulus bit-count for this poly_modulus_degree: "
        << CoeffModulus::MaxBitCount(poly_modulus_degree) << endl;
    cout << "SERVER : Current coeff_modulus bit-count: "
        << context->key_context_data()->total_coeff_modulus_bit_count() << endl;

    CKKSEncoder encoder(context);

    // Create the Evaluator
    Evaluator evaluator(context);

    // Sum the slots
    {
       // Stopwatch sw("SERVER : Sum-the-slots time");
        for (size_t i = 1; i <= encoder.slot_count() / 2; i <<= 1) {
            Ciphertext temp_ct;
            evaluator.rotate_vector(ct, i, galk, temp_ct);
            evaluator.add_inplace(ct, temp_ct);
        }
    }
    return ct;
}

Ciphertext weightedSum(size_t dimension, double scale, Ciphertext ct, GaloisKeys galk)
{
    // Setting up encryption parameters
    EncryptionParameters parms(scheme_type::CKKS);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 30, 60 })); //This time result will be big, so use 60
                                                                                        //so we have 30 bit room for integer output

    // Set up the SEALContext
    auto context = SEALContext::Create(parms);

    cout << "SERVER : Parameters are valid: " << boolalpha
        << context->key_context_data()->qualifiers().parameters_set << endl;
    cout << "SERVER : Maximal allowed coeff_modulus bit-count for this poly_modulus_degree: "
        << CoeffModulus::MaxBitCount(poly_modulus_degree) << endl;
    cout << "SERVER : Current coeff_modulus bit-count: "
        << context->key_context_data()->total_coeff_modulus_bit_count() << endl;

    CKKSEncoder encoder(context);
    vector<double> weights;
    weights.reserve(dimension);
    for (size_t i = 0; i < dimension; i++) {
        weights.push_back((dimension & 1) ? -1.0 : 2.0);
    }

    Plaintext weight_pt;
    {
       // Stopwatch sw("SERVER : Encoding time");
        encoder.encode(weights, scale, weight_pt);
    }

    // Create the Evaluator
    Evaluator evaluator(context);

    {
        //Stopwatch sw("SERVER : Multiply-plain and rescale time");
        evaluator.multiply_plain_inplace(ct, weight_pt);
        evaluator.rescale_to_next_inplace(ct);
    }


    // Sum the slots
    {
       // Stopwatch sw("SERVER : Sum-the-slots time");
        for (size_t i = 1; i <= encoder.slot_count() / 2; i <<= 1) {
            Ciphertext temp_ct;
            evaluator.rotate_vector(ct, i, galk, temp_ct);
            evaluator.add_inplace(ct, temp_ct);
        }
    }
    return ct;
}
