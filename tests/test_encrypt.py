import pytest
from docx_locker.encrypt import generate_docx_protection


@pytest.fixture
def known_good_encrypt_params():
    return {
        'password': 'password',
        'salt': 'ouz9XiaimAE4pO6OOtk28g==',
        'expected_key_hash': 'i0n8VS6iu1JkFdcyinogmBaJ/eQs0vwizOKv38ou83lAPksn1Vm9gtXOw6QpNAU8qVagVXcTZl+q/6tOiYQK0g==',
        'spin_count': 100000,
        'algo_class': 'hash',
        'algo_sid': 14,
        'provider_type': 'rsaAES'
    }


def test_generate_docx_protection_with_known_values(known_good_encrypt_params):
    case = generate_docx_protection(known_good_encrypt_params['password'], known_good_encrypt_params['salt'])
    assert case.key_hash == known_good_encrypt_params['expected_key_hash'], "Key hash does not match expected value"
    assert case.salt_hash == known_good_encrypt_params['salt'], "Salt hash does not match expected value"
    assert case.spin_count == known_good_encrypt_params['spin_count'], "Spin count does not match expected value"
    assert case.algo_class == known_good_encrypt_params['algo_class'], "Algorithm class does not match expected value"
    assert case.algo_sid == known_good_encrypt_params['algo_sid'], "Algorithm SID does not match expected value"
    assert case.provider_type == known_good_encrypt_params['provider_type'], "Provider type does not match expected value"


@pytest.mark.parametrize(
    "password, spins, expected_spin_count",
    [
        ('password', 50000, 50000),
        ('password', 200000, 200000),
        ('password', None, 100000),  # Default spin count
    ]
)
def test_generate_docx_protection_with_custom_spins(password, spins, expected_spin_count):
    case = generate_docx_protection(password, spins=spins)
    assert case.spin_count == expected_spin_count, f"Spin count does not match expected value {expected_spin_count}"
    assert len(case.key_hash) != 0, "Key hash is empty"
    assert len(case.salt_hash) == 24, "Salt hash length is not 24 characters"
    assert case.algo_class == 'hash', "Algorithm class is not 'hash'"
    assert case.algo_sid == 14, "Algorithm SID is not 14"
    assert case.provider_type == 'rsaAES', "Provider type is not 'rsaAES'"


@pytest.mark.parametrize(
    "invalid_args",
    [
        (None,),                 # No arguments
        (1,),                    # Non-string password
        ('password', 1),         # Invalid salt
        ('password', 'salt', 'spins')  # Invalid spins argument
    ]
)
def test_generate_docx_protection_invalid_inputs(invalid_args):
    with pytest.raises(TypeError):
        generate_docx_protection(*invalid_args)
