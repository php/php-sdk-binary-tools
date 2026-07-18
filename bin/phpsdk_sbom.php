<?php

function make_uuid()
{
    $data = random_bytes(16);
    $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
    $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);

    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}

function make_php_cpe($php_version)
{
    $cpe_version = $php_version;
    $cpe_update = '*';
    if (preg_match('/^(\d+\.\d+\.\d+)-?(alpha|beta|rc|dev)(\d*)$/i', $php_version, $matches)) {
        $cpe_version = $matches[1];
        $cpe_update = strtolower($matches[2] . $matches[3]);
    }

    return 'cpe:2.3:a:php:php:' . $cpe_version . ':' . $cpe_update . ':*:*:*:*:*:*';
}

function hash_source_path($php_source_dir, $path)
{
    $source_path = $php_source_dir . '/' . str_replace('\\', '/', $path);
    if (is_file($source_path)) {
        $hash = @hash_file('sha256', $source_path);
        if ($hash === false) {
            echo "ERROR: couldn't hash source path '$path'\n";
            exit(1);
        }
        return array(
            'value' => $hash,
            'format' => 'file-content-v1',
        );
    }
    if (!is_dir($source_path)) {
        echo "ERROR: couldn't find source path '$path'\n";
        exit(1);
    }

    $files = array();
    $base = rtrim(str_replace('\\', '/', $source_path), '/') . '/';
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($source_path, FilesystemIterator::SKIP_DOTS)
    );
    foreach ($it as $file) {
        if ($file->isFile()) {
            $files[str_replace('\\', '/', $file->getPathname())] = $file->getPathname();
        }
    }
    ksort($files, SORT_STRING);

    $context = hash_init('sha256');
    foreach ($files as $normalized => $file) {
        $relative = strpos($normalized, $base) === 0 ? substr($normalized, strlen($base)) : basename($normalized);
        $hash = @hash_file('sha256', $file);
        if ($hash === false) {
            echo "ERROR: couldn't hash source path '$path'\n";
            exit(1);
        }
        hash_update($context, $relative . "\n" . $hash . "\n");
    }

    return array(
        'value' => hash_final($context),
        'format' => 'relative-path-and-file-sha256-v1',
    );
}

function create_cyclonedx_sbom($php_version, $php_license_id, $php_copyright, $source_components, $dependency_sbom_files, $dependency_sbom_status, $dest_file)
{
    $php_ref = 'pkg:generic/php@' . $php_version;
    $php_cpe = make_php_cpe($php_version);
    $php_source_artifact = 'php-' . $php_version . ' source tree';
    $template_file = __DIR__ . '/sbom-templates/cyclonedx.json';
    $template = @file_get_contents($template_file);
    $cyclonedx = $template !== false ? json_decode(strtr($template, array(
        '{{UUID}}' => substr(json_encode(make_uuid()), 1, -1),
        '{{TIMESTAMP}}' => substr(json_encode(gmdate('Y-m-d\TH:i:s\Z')), 1, -1),
        '{{PHP_VERSION}}' => substr(json_encode($php_version), 1, -1),
        '{{PHP_REF}}' => substr(json_encode($php_ref), 1, -1),
        '{{PHP_CPE}}' => substr(json_encode($php_cpe), 1, -1),
        '{{PHP_LICENSE}}' => substr(json_encode($php_license_id), 1, -1),
    )), true) : null;
    if (!is_array($cyclonedx)) {
        echo "ERROR: couldn't parse SBOM template '$template_file'\n";
        exit(1);
    }
    $cyclonedx['metadata']['component']['properties'] = array(
        array(
            'name' => 'php:dependency-sbom-status',
            'value' => $dependency_sbom_status,
        ),
    );
    $cyclonedx['metadata']['component']['copyright'] = $php_copyright;
    $components = array();
    $dependency_refs = array();
    $dependencies = array();
    $vulnerabilities = array();

    foreach ($source_components as $component) {
        $component_version = $component['version'] ?? ('snapshot-' . substr($component['sourceHash'], 0, 12));
        $ref = $component['purl'] ?? ('pkg:generic/php-src/' . preg_replace('/[^A-Za-z0-9._-]/', '-', strtolower($component['name'])));
        $cyclonedx_component = array(
            'type' => 'library',
            'bom-ref' => $ref,
            'name' => $component['name'],
            'version' => $component_version,
            'copyright' => 'See accompanying license and notice files.',
        );
        if (!empty($component['purl'])) {
            $cyclonedx_component['purl'] = $component['purl'];
        }
        if (!empty($component['license']) && $component['license'] !== 'NOASSERTION') {
            $cyclonedx_component['licenses'] = preg_match('/^[A-Za-z0-9.+-]+$/', $component['license'])
                    && strpos($component['license'], 'LicenseRef-') !== 0
                ? array(array('license' => array('id' => $component['license'])))
                : array(array('expression' => $component['license']));
        }
        if (!empty($component['path'])) {
            $cyclonedx_component['hashes'] = array(array(
                'alg' => 'SHA-256',
                'content' => $component['sourceHash'],
            ));
            $cyclonedx_component['properties'] = array(
                array(
                    'name' => 'php:component-origin',
                    'value' => 'bundled',
                ),
                array(
                    'name' => 'php:source-artifact',
                    'value' => $php_source_artifact,
                ),
                array(
                    'name' => 'php:source-path',
                    'value' => $component['path'],
                ),
                array(
                    'name' => 'php:source-digest-algorithm',
                    'value' => 'SHA-256',
                ),
                array(
                    'name' => 'php:source-digest',
                    'value' => $component['sourceHash'],
                ),
                array(
                    'name' => 'php:source-digest-format',
                    'value' => $component['sourceHashFormat'],
                ),
            );
        }

        $components[$ref] = $cyclonedx_component;
        $dependency_refs[$ref] = $ref;
    }

    foreach ($dependency_sbom_files as $file) {
        if (!preg_match('/\.cdx\.json$/', $file)) {
            continue;
        }

        $sbom_text = @file_get_contents($file);
        $sbom = $sbom_text !== false ? json_decode($sbom_text, true) : null;
        if (!is_array($sbom)) {
            echo "ERROR: couldn't parse JSON file '$file'\n";
            exit(1);
        }

        $sbom_components = $sbom['components'] ?? array();
        if (!empty($sbom['metadata']['component']) && is_array($sbom['metadata']['component'])) {
            array_unshift($sbom_components, $sbom['metadata']['component']);
            if (!empty($sbom['metadata']['component']['bom-ref'])) {
                $dependency_refs[$sbom['metadata']['component']['bom-ref']] = $sbom['metadata']['component']['bom-ref'];
            }
        }
        foreach ($sbom_components as $component) {
            if (!is_array($component) || empty($component['name'])) {
                continue;
            }
            if (!empty($component['components'])) {
                $component['components'] = array_values(array_filter(
                    $component['components'],
                    function ($nested_component) {
                        return ($nested_component['type'] ?? '') !== 'file';
                    }
                ));
                if (empty($component['components'])) {
                    unset($component['components']);
                }
            }

            $key = !empty($component['bom-ref'])
                ? $component['bom-ref']
                : $component['name'] . '@' . ($component['version'] ?? '');

            if (!isset($components[$key])) {
                $components[$key] = $component;
            }
        }
        foreach ($sbom['dependencies'] ?? array() as $dependency) {
            if (empty($dependency['ref'])) {
                continue;
            }

            if (!isset($dependencies[$dependency['ref']])) {
                $dependency['dependsOn'] = array_values(array_unique($dependency['dependsOn'] ?? array()));
                $dependencies[$dependency['ref']] = $dependency;
                continue;
            }

            $dependencies[$dependency['ref']]['dependsOn'] = array_values(array_unique(array_merge(
                $dependencies[$dependency['ref']]['dependsOn'] ?? array(),
                $dependency['dependsOn'] ?? array()
            )));
        }
        foreach ($sbom['vulnerabilities'] ?? array() as $vulnerability) {
            $affected_refs = array_column($vulnerability['affects'] ?? array(), 'ref');
            sort($affected_refs, SORT_STRING);
            $key = ($vulnerability['id'] ?? '') . '|' . implode(',', array_unique($affected_refs));
            if (!isset($vulnerabilities[$key])) {
                $vulnerabilities[$key] = $vulnerability;
            }
        }
    }

    $dependencies[$php_ref] = array(
        'ref' => $php_ref,
        'dependsOn' => array_values($dependency_refs),
    );

    $cyclonedx['components'] = array_values($components);
    $cyclonedx['dependencies'] = array_values($dependencies);
    if (!empty($vulnerabilities)) {
        $cyclonedx['vulnerabilities'] = array_values($vulnerabilities);
    }

    if (@file_put_contents($dest_file, json_encode($cyclonedx, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n") === false) {
        echo "ERROR: couldn't write '$dest_file'\n";
        exit(1);
    }
}

function create_spdx_sbom($php_version, $php_license_id, $php_copyright, $source_components, $dependency_sbom_files, $dependency_sbom_status, $dest_file)
{
    $php_spdx_id = 'SPDXRef-PHP';
    $php_ref = 'pkg:generic/php@' . $php_version;
    $php_cpe = make_php_cpe($php_version);
    $php_source_artifact = 'php-' . $php_version . ' source tree';
    $php_version_parts = explode('.', $php_version);
    $php_source_ref = substr($php_version, -4) === '-dev'
        ? 'PHP-' . $php_version_parts[0] . '.' . $php_version_parts[1]
        : 'php-' . $php_version;
    $php_source_base_url = 'https://github.com/php/php-src/tree/' . rawurlencode($php_source_ref) . '/';
    $template_file = __DIR__ . '/sbom-templates/spdx.json';
    $template = @file_get_contents($template_file);
    $created = gmdate('Y-m-d\TH:i:s\Z');
    $spdx = $template !== false ? json_decode(strtr($template, array(
        '{{UUID}}' => substr(json_encode(make_uuid()), 1, -1),
        '{{TIMESTAMP}}' => substr(json_encode($created), 1, -1),
        '{{PHP_VERSION}}' => substr(json_encode($php_version), 1, -1),
        '{{PHP_REF}}' => substr(json_encode($php_ref), 1, -1),
        '{{PHP_CPE}}' => substr(json_encode($php_cpe), 1, -1),
        '{{PHP_LICENSE}}' => substr(json_encode($php_license_id), 1, -1),
    )), true) : null;
    if (!is_array($spdx)) {
        echo "ERROR: couldn't parse SBOM template '$template_file'\n";
        exit(1);
    }
    $spdx['packages'][0]['copyrightText'] = $php_copyright;
    $spdx['packages'][0]['annotations'] = array(
        array(
            'annotationDate' => $created,
            'annotationType' => 'OTHER',
            'annotator' => 'Tool: php-' . $php_version,
            'comment' => 'php:dependency-sbom-status=' . $dependency_sbom_status,
        ),
    );
    $dependency_relationship_template = array(
        'spdxElementId' => $php_spdx_id,
        'relationshipType' => 'DEPENDS_ON',
        'relatedSpdxElement' => '',
    );
    $packages = array($spdx['packages'][0]);
    $relationships = array($spdx['relationships'][0]);
    $extracted_licenses = array();
    $package_ids_by_key = array();
    $relationship_keys = array('SPDXRef-DOCUMENT|DESCRIBES|SPDXRef-PHP' => true);
    $package_count = 0;
    $license_list_version = null;

    foreach ($source_components as $component) {
        $package_count++;
        $component_version = $component['version'] ?? ('snapshot-' . substr($component['sourceHash'], 0, 12));
        $dependency_spdx_id = 'SPDXRef-Source-' . preg_replace('/[^A-Za-z0-9.-]/', '-', $component['name'] . '-' . $component_version . '-' . $package_count);
        $package = array(
            'name' => $component['name'],
            'SPDXID' => $dependency_spdx_id,
            'versionInfo' => $component_version,
            'downloadLocation' => $php_source_base_url . str_replace('\\', '/', $component['path']),
            'filesAnalyzed' => false,
            'licenseConcluded' => $component['license'] ?? 'NOASSERTION',
            'licenseDeclared' => $component['license'] ?? 'NOASSERTION',
            'copyrightText' => 'See accompanying license and notice files.',
            'supplier' => 'Organization: PHP Group',
            'originator' => 'NOASSERTION',
            'primaryPackagePurpose' => 'LIBRARY',
            'sourceInfo' => 'Bundled in ' . $php_source_artifact . ' at ' . $component['path']
                . (!empty($component['sourceHash'])
                    ? '; source digest SHA-256 (' . $component['sourceHashFormat'] . '): ' . $component['sourceHash']
                    : ''),
        );
        if (!empty($component['sourceHash'])) {
            $package['checksums'] = array(array(
                'algorithm' => 'SHA256',
                'checksumValue' => $component['sourceHash'],
            ));
        }
        if (!empty($component['purl'])) {
            $package['externalRefs'] = array(
                array(
                    'referenceCategory' => 'PACKAGE-MANAGER',
                    'referenceType' => 'purl',
                    'referenceLocator' => $component['purl'],
                ),
            );
        }
        if (!empty($component['license']) && strpos($component['license'], 'LicenseRef-') === 0 && !empty($component['licenseText'])) {
            $extracted_licenses[$component['license']] = array(
                'licenseId' => $component['license'],
                'extractedText' => $component['licenseText'],
            );
            if (!empty($component['licenseName'])) {
                $extracted_licenses[$component['license']]['name'] = $component['licenseName'];
            }
        }
        $packages[] = $package;

        $relationships[] = array_merge($dependency_relationship_template, array(
            'relatedSpdxElement' => $dependency_spdx_id,
        ));
        $relationship_keys[$php_spdx_id . '|DEPENDS_ON|' . $dependency_spdx_id] = true;
    }

    foreach ($dependency_sbom_files as $file) {
        if (!preg_match('/\.spdx\.json$/', $file)) {
            continue;
        }

        $sbom_text = @file_get_contents($file);
        $sbom = $sbom_text !== false ? json_decode($sbom_text, true) : null;
        if (!is_array($sbom)) {
            echo "ERROR: couldn't parse JSON file '$file'\n";
            exit(1);
        }
        $dependency_license_list_version = $sbom['creationInfo']['licenseListVersion'] ?? null;
        if ($dependency_license_list_version !== null
                && ($license_list_version === null || version_compare($dependency_license_list_version, $license_list_version, '>'))) {
            $license_list_version = $dependency_license_list_version;
        }

        foreach ($sbom['hasExtractedLicensingInfos'] ?? array() as $license) {
            if (empty($license['licenseId'])) {
                continue;
            }
            $license_id = $license['licenseId'];
            if (isset($extracted_licenses[$license_id])
                    && ($extracted_licenses[$license_id]['extractedText'] ?? '') !== ($license['extractedText'] ?? '')) {
                echo "ERROR: conflicting extracted license text for '$license_id' in '$file'\n";
                exit(1);
            }
            if (!isset($extracted_licenses[$license_id])) {
                $extracted_licenses[$license_id] = $license;
            }
        }

        $spdx_id_map = array();
        foreach ($sbom['packages'] ?? array() as $package) {
            if (empty($package['name'])) {
                continue;
            }
            $original_spdx_id = $package['SPDXID'] ?? null;
            $package['filesAnalyzed'] = false;
            unset($package['packageVerificationCode'], $package['licenseInfoFromFiles']);

            $package_purl = '';
            foreach ($package['externalRefs'] ?? array() as $external_ref) {
                if (($external_ref['referenceType'] ?? '') === 'purl') {
                    $package_purl = $external_ref['referenceLocator'] ?? '';
                    break;
                }
            }
            $package_key = json_encode(array(
                $package['name'],
                $package['versionInfo'] ?? '',
                $package['packageFileName'] ?? '',
                $package['downloadLocation'] ?? '',
                $package_purl,
            ), JSON_UNESCAPED_SLASHES);

            if (isset($package_ids_by_key[$package_key])) {
                $dependency_spdx_id = $package_ids_by_key[$package_key];
            } else {
                $package_count++;
                $dependency_spdx_id = 'SPDXRef-Dependency-' . preg_replace('/[^A-Za-z0-9.-]/', '-', $package['name'] . '-' . ($package['versionInfo'] ?? 'NOASSERTION') . '-' . $package_count);
                $package['SPDXID'] = $dependency_spdx_id;
                $packages[] = $package;
                $package_ids_by_key[$package_key] = $dependency_spdx_id;
            }
            if ($original_spdx_id !== null) {
                $spdx_id_map[$original_spdx_id] = $dependency_spdx_id;
            }
        }

        foreach ($sbom['documentDescribes'] ?? array() as $described) {
            $dependency_spdx_id = $spdx_id_map[$described] ?? null;
            $key = $php_spdx_id . '|DEPENDS_ON|' . $dependency_spdx_id;
            if ($dependency_spdx_id !== null && !isset($relationship_keys[$key])) {
                $relationships[] = array_merge($dependency_relationship_template, array(
                    'relatedSpdxElement' => $dependency_spdx_id,
                ));
                $relationship_keys[$key] = true;
            }
        }

        foreach ($sbom['relationships'] ?? array() as $relationship) {
            $from = $spdx_id_map[$relationship['spdxElementId'] ?? ''] ?? null;
            $to = $spdx_id_map[$relationship['relatedSpdxElement'] ?? ''] ?? null;
            $type = $relationship['relationshipType'] ?? '';
            $key = $from . '|' . $type . '|' . $to;
            if ($from !== null && $to !== null && $from !== $to && $type !== '' && !isset($relationship_keys[$key])) {
                $relationships[] = array(
                    'spdxElementId' => $from,
                    'relationshipType' => $type,
                    'relatedSpdxElement' => $to,
                );
                $relationship_keys[$key] = true;
            }
        }
    }

    $spdx['packages'] = $packages;
    $spdx['relationships'] = $relationships;
    if ($license_list_version !== null) {
        $spdx['creationInfo']['licenseListVersion'] = $license_list_version;
    }
    if (!empty($extracted_licenses)) {
        $spdx['hasExtractedLicensingInfos'] = array_values($extracted_licenses);
    }

    if (@file_put_contents($dest_file, json_encode($spdx, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n") === false) {
        echo "ERROR: couldn't write '$dest_file'\n";
        exit(1);
    }
}

function create_openvex($php_version, $dependency_sbom_files, $dest_file)
{
    $template_file = __DIR__ . '/sbom-templates/openvex.json';
    $template = @file_get_contents($template_file);
    $openvex = $template !== false ? json_decode(strtr($template, array(
        '{{UUID}}' => substr(json_encode(make_uuid()), 1, -1),
        '{{TIMESTAMP}}' => substr(json_encode(gmdate('Y-m-d\TH:i:s\Z')), 1, -1),
        '{{PHP_VERSION}}' => substr(json_encode($php_version), 1, -1),
    )), true) : null;
    if (!is_array($openvex)) {
        echo "ERROR: couldn't parse SBOM template '$template_file'\n";
        exit(1);
    }
    $statements = array();
    foreach ($dependency_sbom_files as $file) {
        if (!preg_match('/\.openvex\.json$/', $file)) {
            continue;
        }

        $vex_text = @file_get_contents($file);
        $vex = $vex_text !== false ? json_decode($vex_text, true) : null;
        if (!is_array($vex)) {
            echo "ERROR: couldn't parse JSON file '$file'\n";
            exit(1);
        }

        $statements = array_merge($statements, $vex['statements'] ?? array());
    }

    if (empty($statements)) {
        return;
    }

    $openvex['statements'] = $statements;
    if (@file_put_contents($dest_file, json_encode($openvex, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n") === false) {
        echo "ERROR: couldn't write '$dest_file'\n";
        exit(1);
    }
}

function export_sbom_files($artifact_file)
{
    $artifact_file = str_replace('\\', '/', $artifact_file);
    $artifact_name = basename($artifact_file);
    if (!is_file($artifact_file)) {
        echo "ERROR: PHP archive '$artifact_file' does not exist\n";
        exit(1);
    }
    if (!preg_match('/^php-([0-9].+?)(-nts)?-Win32-(v[sc]\d+)-(x86|x64|arm64)\.zip$/i', $artifact_name, $matches)) {
        echo "ERROR: unsupported PHP archive name '$artifact_name'\n";
        exit(1);
    }

    $zip = new ZipArchive();
    if ($zip->open($artifact_file) !== true) {
        echo "ERROR: couldn't open PHP archive '$artifact_file'\n";
        exit(1);
    }
    $documents = array();
    foreach (array('cdx', 'spdx', 'openvex') as $format) {
        $contents = $zip->getFromName('extras/sbom/php.' . $format . '.json');
        if ($contents === false) {
            if ($format === 'openvex') {
                continue;
            }
            $zip->close();
            echo "ERROR: PHP archive '$artifact_file' does not contain php.$format.json\n";
            exit(1);
        }
        $documents[$format] = $contents;
    }
    $zip->close();

    $artifact_version = $matches[1];
    $thread_safety = $matches[2] === '-nts' ? 'nts' : 'ts';
    $compiler = $matches[3];
    $architecture = $matches[4];
    $directory = preg_match('/^\d+\.\d+\.\d+$/', $artifact_version) ? 'releases' : 'qa';
    $download_location = 'https://downloads.php.net/~windows/' . $directory . '/' . $artifact_name;
    $hash = @hash_file('sha256', $artifact_file);
    if ($hash === false) {
        echo "ERROR: couldn't hash PHP archive '$artifact_file'\n";
        exit(1);
    }

    $cyclonedx = json_decode($documents['cdx'], true);
    if (!is_array($cyclonedx) || !isset($cyclonedx['metadata']['component'])) {
        echo "ERROR: couldn't parse CycloneDX SBOM in '$artifact_file'\n";
        exit(1);
    }
    $cyclonedx['metadata']['component']['hashes'] = array(array(
        'alg' => 'SHA-256',
        'content' => $hash,
    ));
    $cyclonedx['metadata']['component']['externalReferences'] = array(array(
        'type' => 'distribution',
        'url' => $download_location,
    ));
    $cyclonedx['metadata']['component']['properties'] = array_merge(
        $cyclonedx['metadata']['component']['properties'] ?? array(),
        array(
            array('name' => 'php:artifact-file-name', 'value' => $artifact_name),
            array('name' => 'php:artifact-download-location', 'value' => $download_location),
            array('name' => 'php:artifact-architecture', 'value' => $architecture),
            array('name' => 'php:artifact-thread-safety', 'value' => $thread_safety),
            array('name' => 'php:artifact-compiler', 'value' => $compiler),
        )
    );
    if (@file_put_contents(
        $artifact_file . '.cdx.json',
        json_encode($cyclonedx, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n"
    ) === false) {
        echo "ERROR: couldn't write CycloneDX SBOM for '$artifact_file'\n";
        exit(1);
    }

    $spdx = json_decode($documents['spdx'], true);
    if (!is_array($spdx) || !is_array($spdx['packages'] ?? null)) {
        echo "ERROR: couldn't parse SPDX SBOM in '$artifact_file'\n";
        exit(1);
    }
    $spdx['documentNamespace'] = $download_location . '.spdx.json';
    $php_package = null;
    foreach ($spdx['packages'] as &$package) {
        if (($package['SPDXID'] ?? null) === 'SPDXRef-PHP') {
            $php_package = &$package;
            break;
        }
    }
    if ($php_package === null) {
        echo "ERROR: SPDX SBOM in '$artifact_file' does not describe SPDXRef-PHP\n";
        exit(1);
    }
    $php_package['packageFileName'] = $artifact_name;
    $php_package['downloadLocation'] = $download_location;
    $php_package['checksums'] = array(array(
        'algorithm' => 'SHA256',
        'checksumValue' => $hash,
    ));
    unset($php_package, $package);
    if (@file_put_contents(
        $artifact_file . '.spdx.json',
        json_encode($spdx, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n"
    ) === false) {
        echo "ERROR: couldn't write SPDX SBOM for '$artifact_file'\n";
        exit(1);
    }

    if (isset($documents['openvex']) && @file_put_contents(
        $artifact_file . '.openvex.json',
        $documents['openvex']
    ) === false) {
        echo "ERROR: couldn't write OpenVEX document for '$artifact_file'\n";
        exit(1);
    }
}

function add_dependency_compliance_files($php_version, $php_source_dir, $php_build_dir, $dist_dir)
{
    $licenses_dir = $php_build_dir . '/share/licenses';
    $source_sbom_file = $php_source_dir . '/win32/build/sbom.json';
    $sbom_dir = $php_build_dir . '/share/sbom';
    $dist_sbom_dir = $dist_dir . '/extras/sbom';
    $license_templates = array(
        'section' => "\n\nWindows binary dependency licenses\n===================================\n{licenses}",
        'library' => "\n\n{library}\n{underline}\n",
        'file' => "\n{file}\n{underline}\n\n{text}\n",
    );
    $php_license = @file_get_contents($php_source_dir . '/LICENSE');
    if ($php_license === false || !preg_match('/^Copyright .*The PHP Group.*$/m', $php_license, $matches)) {
        echo "ERROR: couldn't read PHP copyright notice\n";
        exit(1);
    }
    $php_copyright = trim($matches[0]);

    if (is_dir($dist_sbom_dir)) {
        $it = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($dist_sbom_dir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );
        foreach ($it as $item) {
            $path = $item->getPathname();
            $removed = $item->isDir() && !$item->isLink() ? @rmdir($path) : @unlink($path);
            if (!$removed) {
                echo "ERROR: couldn't remove stale SBOM path '$path'\n";
                exit(1);
            }
        }
        if (!@rmdir($dist_sbom_dir)) {
            echo "ERROR: couldn't remove stale SBOM directory '$dist_sbom_dir'\n";
            exit(1);
        }
    }

    if (is_dir($licenses_dir)) {
        $license_dirs = glob($licenses_dir . '/*', GLOB_ONLYDIR);
        if (!empty($license_dirs)) {
            sort($license_dirs, SORT_STRING);
            $license_text = '';

            foreach ($license_dirs as $license_dir) {
                $license_files = array();
                $it = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($license_dir, FilesystemIterator::SKIP_DOTS)
                );
                foreach ($it as $file) {
                    if ($file->isFile()) {
                        $license_files[] = $file->getPathname();
                    }
                }
                if (empty($license_files)) {
                    continue;
                }
                sort($license_files, SORT_STRING);

                $library = basename($license_dir);
                $license_text .= strtr($license_templates['library'], array(
                    '{library}' => $library,
                    '{underline}' => str_repeat("-", strlen($library)),
                ));
                foreach ($license_files as $license_file) {
                    $base = rtrim(str_replace('\\', '/', $license_dir), '/') . '/';
                    $path = str_replace('\\', '/', $license_file);
                    $relative = strpos($path, $base) === 0 ? substr($path, strlen($base)) : basename($path);
                    $relative = $library . '/' . $relative;
                    $contents = @file_get_contents($license_file);
                    if ($contents === false) {
                        echo "ERROR: couldn't read dependency license '$license_file'\n";
                        exit(1);
                    }
                    $contents = rtrim(str_replace(array("\r\n", "\r"), "\n", $contents));

                    $license_text .= strtr($license_templates['file'], array(
                        '{file}' => $relative,
                        '{underline}' => str_repeat("~", strlen($relative)),
                        '{text}' => $contents,
                    ));
                }
            }

            if ($license_text !== '') {
                $readme_file = $dist_dir . '/readme-redist-bins.txt';
                $text = @file_get_contents($readme_file);
                if ($text === false) {
                    echo "ERROR: couldn't read readme-redist-bins.txt\n";
                    exit(1);
                }
                $text = str_replace(array("\r\n", "\r"), "\n", $text);
                $section_header = str_replace('{licenses}', '', $license_templates['section']);
                $section_start = strpos($text, $section_header);
                if ($section_start !== false) {
                    $text = substr($text, 0, $section_start);
                }
                $text .= strtr($license_templates['section'], array(
                    '{licenses}' => $license_text,
                ));
                $text = str_replace("\n", "\r\n", $text);
                if (@file_put_contents($readme_file, $text) === false) {
                    echo "ERROR: couldn't write dependency licenses to readme-redist-bins.txt\n";
                    exit(1);
                }
            }
        }
    }

    $source_sbom_text = @file_get_contents($source_sbom_file);
    $source_sbom = $source_sbom_text !== false ? json_decode($source_sbom_text, true) : null;
    if (
        !is_array($source_sbom)
        || !is_string($source_sbom['license'] ?? null)
        || $source_sbom['license'] === ''
        || !is_array($source_sbom['components'] ?? null)
    ) {
        echo "ERROR: couldn't parse source SBOM metadata '$source_sbom_file'\n";
        exit(1);
    }
    $php_license_id = $source_sbom['license'];
    $source_components = $source_sbom['components'];
    foreach ($source_components as $source_component) {
        if (!is_array($source_component) || empty($source_component['name']) || empty($source_component['path'])) {
            echo "ERROR: couldn't parse source SBOM metadata '$source_sbom_file'\n";
            exit(1);
        }
    }
    foreach ($source_components as $i => $source_component) {
        $source_hash = hash_source_path($php_source_dir, $source_component['path']);
        $source_components[$i]['sourceHash'] = $source_hash['value'];
        $source_components[$i]['sourceHashFormat'] = $source_hash['format'];
    }

    $sbom_files = is_dir($sbom_dir) ? glob($sbom_dir . '/*.json') : array();
    if (empty($sbom_files) && empty($source_components)) {
        return;
    }
    sort($sbom_files, SORT_STRING);
    $dependency_formats = array();
    foreach ($sbom_files as $file) {
        if (preg_match('/^(.*)\.(cdx|spdx)\.json$/', basename($file), $matches)) {
            $dependency_formats[$matches[1]][$matches[2]] = true;
        }
    }
    // "present" describes discovered format pairs, not complete dependency coverage.
    $dependency_sbom_status = empty($dependency_formats) ? 'unavailable' : 'present';
    foreach ($dependency_formats as $formats) {
        if (count($formats) !== 2) {
            $dependency_sbom_status = 'partial';
            break;
        }
    }

    if (!is_dir($dist_sbom_dir) && !@mkdir($dist_sbom_dir, 0777, true)) {
        echo "ERROR: couldn't create '$dist_sbom_dir'\n";
        exit(1);
    }

    create_cyclonedx_sbom($php_version, $php_license_id, $php_copyright, $source_components, $sbom_files, $dependency_sbom_status, $dist_sbom_dir . '/php.cdx.json');
    create_spdx_sbom($php_version, $php_license_id, $php_copyright, $source_components, $sbom_files, $dependency_sbom_status, $dist_sbom_dir . '/php.spdx.json');
    create_openvex($php_version, $sbom_files, $dist_sbom_dir . '/php.openvex.json');
}

if (($argv[1] ?? null) === '--export') {
    if (count($argv) !== 3) {
        fwrite(STDERR, "Usage: phpsdk_sbom --export <php-archive>\n");
        exit(2);
    }
    export_sbom_files($argv[2]);
    exit(0);
}

if (count($argv) !== 5) {
    fwrite(STDERR, "Usage: phpsdk_sbom <php-version> <php-source-dir> <php-build-dir> <dist-dir>\n");
    exit(2);
}

$php_version = $argv[1];
$php_source_dir = rtrim(str_replace('\\', '/', $argv[2]), '/');
$php_build_dir = rtrim(str_replace('\\', '/', $argv[3]), '/');
$dist_dir = rtrim(str_replace('\\', '/', $argv[4]), '/');

if (!is_dir($php_source_dir)) {
    fwrite(STDERR, "ERROR: PHP source directory '$php_source_dir' does not exist\n");
    exit(2);
}
if (!is_dir($dist_dir)) {
    fwrite(STDERR, "ERROR: distribution directory '$dist_dir' does not exist\n");
    exit(2);
}

add_dependency_compliance_files($php_version, $php_source_dir, $php_build_dir, $dist_dir);
