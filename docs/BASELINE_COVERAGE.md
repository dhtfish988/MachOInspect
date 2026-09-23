# Baseline scenario coverage

Baseline commit: `dcd69fcc7475767540a2b496c6415e9adaa83b56`. The isolated baseline ran 134 parameterized cases. This inventory lists each source test function once and maps its behavior to the new native suite(s). It is not a claim that test function names or case counts are preserved.

Native sources: `tests/unit/core_tests.cpp`, `resource_tests.cpp`, `rule_tests.cpp`, `boundary_tests.cpp`, `tests/integration/macos_contract.cpp`, and `tools/verify_system.cpp`. Final native logs record 442 executed assertions across five programs.

Intentional changes have native regression checks and are documented in MIGRATION.md: empty encoded DER is an error; the new schema and API replace Python objects; flag/wording representations follow the new report contract. Structural refusals extend the baseline.

## test_macho.py

core-contract + boundary-contract (image widths, byte order, architecture, segment protections, structural bounds); macos-integration (real files).

| Baseline scenario | New coverage |
|---|---|
| `test_parses_a_minimal_thin_header` (line 28) | Suite behavior above |
| `test_arch_names_match_lipo_conventions` (line 36) | Suite behavior above |
| `test_x86_64_and_x86_64h_are_not_collapsed` (line 43) | Suite behavior above |
| `test_flag_names_are_reported` (line 50) | Suite behavior above |
| `test_segment_protection_helpers` (line 56) | Suite behavior above |
| `test_empty_and_tiny_input_is_refused` (line 67) | Suite behavior above |
| `test_wrong_magic_is_refused` (line 73) | Suite behavior above |
| `test_truncated_header_is_refused` (line 78) | Suite behavior above |
| `test_implausible_command_count_is_refused` (line 83) | Suite behavior above |
| `test_load_commands_past_end_of_file_are_refused` (line 89) | Suite behavior above |
| `test_zero_length_command_is_refused_rather_than_looping` (line 94) | Suite behavior above |
| `test_command_overrunning_sizeofcmds_is_refused` (line 101) | Suite behavior above |
| `test_implausible_fat_arch_count_is_refused` (line 107) | Suite behavior above |
| `test_fat_slice_offset_past_end_is_refused` (line 113) | Suite behavior above |
| `test_reads_a_real_fat_binary` (line 124) | Suite behavior above |

## test_blobs.py

core-contract + boundary-contract (directory versions, flags, hashes, slots, CMS, malformed containers); inspect-verify-system (real hashes).

| Baseline scenario | New coverage |
|---|---|
| `test_v20400_reads_the_exec_segment_fields` (line 83) | Suite behavior above |
| `test_v20100_has_no_team_id_and_none_is_invented` (line 92) | Suite behavior above |
| `test_v20200_reads_a_team_id` (line 99) | Suite behavior above |
| `test_identifier_is_read` (line 105) | Suite behavior above |
| `test_flag_decoding` (line 114) | Suite behavior above |
| `test_cdhash_is_the_digest_of_the_whole_directory` (line 121) | Suite behavior above |
| `test_page_size_is_decoded_from_the_shift` (line 129) | Suite behavior above |
| `test_best_hash_type_prefers_the_strongest_directory` (line 134) | Suite behavior above |
| `test_entitlement_slots_are_extracted` (line 144) | Suite behavior above |
| `test_cms_blob_is_recognised` (line 158) | Suite behavior above |
| `test_adhoc_signature_has_no_cms` (line 167) | Suite behavior above |
| `test_wrong_superblob_magic_is_refused` (line 176) | Suite behavior above |
| `test_signature_without_a_code_directory_is_refused` (line 181) | Suite behavior above |
| `test_implausible_blob_count_is_refused` (line 189) | Suite behavior above |
| `test_blob_offset_past_the_buffer_is_refused` (line 195) | Suite behavior above |
| `test_blob_with_an_impossible_length_is_refused` (line 202) | Suite behavior above |
| `test_truncated_superblob_is_refused` (line 209) | Suite behavior above |
| `test_cdhash_matches_codesign_on_a_real_binary` (line 220) | Suite behavior above |

## test_entitlements.py

core-contract + boundary-contract (typed plist/DER, container grammar, invalid encodings, agreement/difference reporting).

| Baseline scenario | New coverage |
|---|---|
| `test_boolean_values` (line 58) | Suite behavior above |
| `test_string_and_integer_values` (line 63) | Suite behavior above |
| `test_array_value` (line 69) | Suite behavior above |
| `test_empty_array_value` (line 74) | Suite behavior above |
| `test_dictionary_value` (line 78) | Suite behavior above |
| `test_array_of_dictionaries` (line 84) | Suite behavior above |
| `test_long_form_length_is_handled` (line 91) | Suite behavior above |
| `test_empty_blob_is_an_empty_mapping` (line 97) | Intentional change: reject empty encoding; accept encoded empty dictionary |
| `test_wrong_outer_tag_is_refused` (line 105) | Suite behavior above |
| `test_missing_version_is_refused` (line 110) | Suite behavior above |
| `test_unsupported_version_is_refused` (line 115) | Suite behavior above |
| `test_truncated_blob_is_refused` (line 121) | Suite behavior above |
| `test_length_running_past_the_buffer_is_refused` (line 127) | Suite behavior above |
| `test_non_string_key_is_refused` (line 132) | Suite behavior above |
| `test_unknown_value_tag_is_refused` (line 139) | Suite behavior above |
| `test_deep_nesting_is_bounded` (line 146) | Suite behavior above |
| `test_plist_decoding` (line 159) | Suite behavior above |
| `test_plist_tolerates_a_trailing_nul` (line 165) | Suite behavior above |
| `test_malformed_plist_is_refused` (line 171) | Suite behavior above |
| `test_plist_that_is_not_a_dict_is_refused` (line 176) | Suite behavior above |
| `test_compare_reports_nothing_when_the_slots_agree` (line 183) | Suite behavior above |
| `test_compare_names_keys_present_in_only_one_slot` (line 187) | Suite behavior above |
| `test_compare_reports_a_differing_value` (line 193) | Suite behavior above |
| `test_compare_is_silent_when_a_slot_is_absent` (line 198) | Suite behavior above |

## test_audit.py

rule-contract + core-contract (rule decisions, sources, severity, JSON and sorting); macos-integration (actual signed files/errors).

| Baseline scenario | New coverage |
|---|---|
| `test_unsigned_executable_is_high` (line 38) | Suite behavior above |
| `test_linker_signed_binary_is_adhoc` (line 46) | Suite behavior above |
| `test_hardened_runtime_is_detected_and_not_flagged` (line 55) | Suite behavior above |
| `test_missing_hardened_runtime_is_flagged_on_a_non_platform_binary` (line 62) | Suite behavior above |
| `test_risky_entitlements_are_reported` (line 73) | Suite behavior above |
| `test_jit_entitlement_is_medium_not_high` (line 82) | Suite behavior above |
| `test_an_entitlement_set_to_false_grants_nothing` (line 88) | Suite behavior above |
| `test_entitlements_are_read_from_the_der_slot` (line 98) | Suite behavior above |
| `test_matching_entitlement_slots_raise_no_mismatch` (line 108) | Suite behavior above |
| `test_entitlement_risk_table` (line 112) | Suite behavior above |
| `test_entitlement_risk_falls_back_to_prefix_rules` (line 119) | Suite behavior above |
| `test_missing_pie_is_high` (line 131) | Suite behavior above |
| `test_a_normal_binary_is_not_flagged_for_pie` (line 138) | Suite behavior above |
| `test_apple_platform_binaries_are_not_flagged_for_hardened_runtime` (line 147) | Suite behavior above |
| `test_apple_platform_binaries_are_not_flagged_for_a_missing_team_id` (line 155) | Suite behavior above |
| `test_a_signed_system_binary_has_no_high_findings` (line 160) | Suite behavior above |
| `test_a_non_macho_file_reports_an_error_not_a_crash` (line 169) | Suite behavior above |
| `test_a_missing_file_reports_an_error` (line 176) | Suite behavior above |
| `test_truncated_macho_reports_an_error` (line 181) | Suite behavior above |
| `test_findings_are_sorted_worst_first` (line 188) | Suite behavior above |
| `test_report_serialises_to_json_safe_types` (line 196) | Suite behavior above |

## test_cli.py

macos-integration (compiled CLI options, status, paths, traversal, filtering, output); core-contract (report schema).

| Baseline scenario | New coverage |
|---|---|
| `test_default_run_succeeds` (line 29) | Suite behavior above |
| `test_nothing_to_audit_exits_2` (line 33) | Suite behavior above |
| `test_a_directory_without_recursive_exits_2` (line 37) | Suite behavior above |
| `test_fail_on_high_exits_1_when_a_high_finding_exists` (line 43) | Suite behavior above |
| `test_fail_on_high_exits_0_for_a_clean_binary` (line 48) | Suite behavior above |
| `test_fail_on_never_is_the_default` (line 53) | Suite behavior above |
| `test_fail_on_info_catches_everything` (line 59) | Suite behavior above |
| `test_json_output_shape` (line 68) | Suite behavior above |
| `test_min_severity_hides_lower_findings` (line 85) | Suite behavior above |
| `test_verbose_includes_the_reasoning` (line 93) | Suite behavior above |
| `test_summary_mode_prints_totals_only` (line 104) | Suite behavior above |
| `test_no_colour_emits_no_escape_sequences` (line 113) | Suite behavior above |
| `test_recursive_walk_finds_binaries` (line 119) | Suite behavior above |
| `test_recursive_walk_skips_non_macho_files` (line 127) | Suite behavior above |
| `test_parser_rejects_an_unknown_severity` (line 138) | Compiled CLI contract replaces Python parser API |
| `test_parser_defaults` (line 143) | Compiled CLI contract replaces Python parser API |
| `test_path_is_required` (line 150) | Suite behavior above |
| `test_looks_macho_recognises_the_magics` (line 155) | Suite behavior above |

## test_resources.py

resource-contract + macos-integration (layout, seal entries, rules, path/link controls, real codesign changes).

| Baseline scenario | New coverage |
|---|---|
| `test_find_bundle_macos_layout` (line 83) | Suite behavior above |
| `test_find_bundle_flat_layout` (line 92) | Suite behavior above |
| `test_find_bundle_rejects_plain_directory` (line 104) | Suite behavior above |
| `test_clean_bundle_has_no_findings` (line 115) | Suite behavior above |
| `test_modified_resource_is_a_mismatch` (line 126) | Suite behavior above |
| `test_deleted_resource_is_missing` (line 142) | Suite behavior above |
| `test_added_resource_is_reported_as_unsealed` (line 149) | Suite behavior above |
| `test_file_omitted_by_the_rules_is_not_reported` (line 159) | Suite behavior above |
| `test_highest_weight_rule_wins` (line 168) | Suite behavior above |
| `test_equal_weight_rules_keep_document_order` (line 176) | Suite behavior above |
| `test_symlink_target_change_is_reported` (line 183) | Suite behavior above |
| `test_sealed_symlink_that_became_a_file_is_a_type_change` (line 194) | Suite behavior above |
| `test_nested_code_that_is_absent_is_missing` (line 201) | Suite behavior above |
| `test_nested_code_that_is_present_is_not_hash_checked` (line 210) | Suite behavior above |
| `test_a_path_that_escapes_the_bundle_is_not_followed` (line 227) | Suite behavior above |
| `test_parent_symlink_cannot_escape_for_hashing` (line 240) | Suite behavior above |
| `test_parent_symlink_inside_bundle_still_hashes` (line 252) | Suite behavior above |
| `test_sealed_leaf_symlink_is_compared_without_following_target` (line 259) | Suite behavior above |
| `test_executable_name_must_be_a_filename` (line 268) | Suite behavior above |
| `test_executable_symlink_cannot_leave_bundle` (line 275) | Suite behavior above |
| `test_info_plist_symlink_cannot_leave_bundle` (line 285) | Suite behavior above |
| `test_resource_seal_symlink_cannot_leave_bundle` (line 295) | Suite behavior above |
| `test_nested_code_symlink_cannot_leave_bundle` (line 307) | Suite behavior above |
| `test_unknown_digest_size_is_reported_not_guessed` (line 315) | Suite behavior above |
| `test_seal_that_does_not_parse_is_reported` (line 322) | Suite behavior above |
| `test_seal_hash_mismatch_is_reported` (line 330) | Suite behavior above |
| `test_seal_hash_match_is_recorded` (line 340) | Suite behavior above |
| `test_recorded_seal_that_is_absent_is_reported` (line 352) | Suite behavior above |
| `test_many_problems_are_capped_and_counted` (line 361) | Suite behavior above |
| `test_codesign_signed_bundle_is_clean` (line 401) | Suite behavior above |
| `test_modified_resource_agrees_with_codesign` (line 414) | Suite behavior above |
| `test_added_resource_agrees_with_codesign` (line 425) | Suite behavior above |
| `test_removed_resource_agrees_with_codesign` (line 436) | Suite behavior above |
| `test_audit_bundle_files_the_report_under_the_bundle` (line 446) | Suite behavior above |
| `test_tampered_bundle_fails_the_cli_gate` (line 460) | Suite behavior above |

Total source test functions: 131. Parameterization accounts for the larger executed baseline case count.
