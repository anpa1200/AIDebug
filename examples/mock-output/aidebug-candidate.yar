rule AIDebug_Toy_Xor_Config_Decode {
    meta:
        description = "Mock AIDebug YARA seed for a benign toy XOR loop"
        author = "Andrey Pautov"
        source = "AIDebug examples/mock-output"
        confidence = "low"
        review_required = true
    strings:
        $toy_name = "toy_xor_config" ascii
        $xor_hint = "byte ^ key" ascii
    condition:
        any of them
}
