<?php

declare(strict_types=1);

/*
 * This file is part of the Nelmio SecurityBundle.
 *
 * (c) Nelmio <hello@nelm.io>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nelmio\SecurityBundle\ContentSecurityPolicy\Violation;

use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Exception\InvalidPayloadException;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Exception\MissingCspReportException;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Exception\NoDataException;
use Symfony\Component\HttpFoundation\Request;

/**
 * @phpstan-type ReportData array{document-uri?: string, referrer?: string, blocked-uri?: string|null, effective-directive?: string|null, violated-directive?: string, original-policy?: string, disposition?: string, status-code?: int, script-sample?: string, source-file?: string, line-number?: int, column-number?: int}
 */
final class Report
{
    private const NULL_DEFAULTS_FOR_REQUEST_REPORTS = ['effective-directive' => null, 'blocked-uri' => null];

    /**
     * @var array<string, int|string|null>
     *
     * @phpstan-var ReportData
     */
    private array $data;

    private ?string $userAgent;

    /**
     * @param array<string, int|string|null> $data
     *
     * @phpstan-param ReportData $data
     */
    public function __construct(array $data = [], ?string $userAgent = null)
    {
        $this->data = self::keepWellTypedFields($data);
        $this->userAgent = $userAgent;
    }

    /**
     * @param string|int $value
     *
     * @phpstan-template K of key-of<ReportData>
     *
     * @phpstan-param K $key
     * @phpstan-param ReportData[K] $value
     */
    public function setProperty(string $key, $value): self
    {
        $property = self::keepWellTypedFields([$key => $value]);

        if ([] === $property) {
            throw new \TypeError(\sprintf('Report has no "%s" property accepting %s.', $key, get_debug_type($value)));
        }

        $this->data = array_merge($this->data, $property);

        return $this;
    }

    public function getDirective(): ?string
    {
        if (isset($this->data['effective-directive'])) {
            return $this->data['effective-directive'];
        }

        if (isset($this->data['violated-directive'])) {
            $parts = explode(' ', $this->data['violated-directive'], 2);

            return $parts[0];
        }

        return null;
    }

    public function getUri(): ?string
    {
        return $this->data['blocked-uri'] ?? null;
    }

    public function getScriptSample(): ?string
    {
        return $this->data['script-sample'] ?? null;
    }

    public function getDomain(): ?string
    {
        if (null === $uri = $this->getUri()) {
            return null;
        }

        $host = parse_url($uri, \PHP_URL_HOST);

        if (null !== $host && false !== $host) {
            return $host;
        }

        return strtolower($uri);
    }

    public function getScheme(): ?string
    {
        if (null === $uri = $this->getUri()) {
            return null;
        }

        if (false === $pos = strpos($uri, '://')) {
            return null;
        }

        return strtolower(substr($uri, 0, $pos));
    }

    public function isData(): bool
    {
        if (null === $uri = $this->getUri()) {
            return false;
        }

        if (str_starts_with($uri, 'data:')) {
            return true;
        }

        return 'data' === $uri;
    }

    public function getSourceFile(): ?string
    {
        return $this->data['source-file'] ?? null;
    }

    /**
     * @return array<string, int|string|null>
     *
     * @phpstan-return ReportData
     */
    public function getData(): array
    {
        return $this->data;
    }

    public function getUserAgent(): ?string
    {
        return $this->userAgent;
    }

    public static function fromRequest(Request $request): self
    {
        $content = $request->getContent();

        if ('' === $content) {
            throw new NoDataException('Content-Security-Policy Endpoint called without data', 411);
        }

        $json = @json_decode($content, true);

        if (\JSON_ERROR_NONE !== json_last_error()) {
            throw new InvalidPayloadException('Content-Security-Policy Endpoint called with invalid JSON data', 400);
        }

        if (!\is_array($json) || !isset($json['csp-report'])) {
            throw new MissingCspReportException('Content-Security-Policy Endpoint called without "csp-report" data', 400);
        }

        $report = $json['csp-report'];

        if (!\is_array($report) || [] === $report) {
            return new self();
        }

        $data = self::keepWellTypedFields($report);

        if ([] === $data) {
            throw new InvalidPayloadException('Content-Security-Policy Endpoint called without any valid "csp-report" field', 400);
        }

        if (!isset($data['effective-directive']) && isset($data['violated-directive'])) {
            $data['effective-directive'] = explode(' ', $data['violated-directive'], 2)[0];
        }

        $requestReport = new self($data, $request->headers->get('User-Agent'));
        $requestReport->data += self::NULL_DEFAULTS_FOR_REQUEST_REPORTS;

        return $requestReport;
    }

    /**
     * @param array<mixed> $fields
     *
     * @phpstan-return ReportData
     */
    private static function keepWellTypedFields(array $fields): array
    {
        return array_filter([
            'document-uri' => self::stringOrNull($fields, 'document-uri'),
            'referrer' => self::stringOrNull($fields, 'referrer'),
            'blocked-uri' => self::stringOrNull($fields, 'blocked-uri'),
            'effective-directive' => self::stringOrNull($fields, 'effective-directive'),
            'violated-directive' => self::stringOrNull($fields, 'violated-directive'),
            'original-policy' => self::stringOrNull($fields, 'original-policy'),
            'disposition' => self::stringOrNull($fields, 'disposition'),
            'status-code' => self::intOrNull($fields, 'status-code'),
            'script-sample' => self::stringOrNull($fields, 'script-sample'),
            'source-file' => self::stringOrNull($fields, 'source-file'),
            'line-number' => self::intOrNull($fields, 'line-number'),
            'column-number' => self::intOrNull($fields, 'column-number'),
        ], static fn ($value): bool => null !== $value);
    }

    /**
     * @param array<mixed> $fields
     */
    private static function stringOrNull(array $fields, string $key): ?string
    {
        return isset($fields[$key]) && \is_string($fields[$key]) ? $fields[$key] : null;
    }

    /**
     * @param array<mixed> $fields
     */
    private static function intOrNull(array $fields, string $key): ?int
    {
        $value = $fields[$key] ?? null;

        if (\is_int($value)) {
            return $value;
        }

        if (\is_string($value) && false !== $int = filter_var($value, \FILTER_VALIDATE_INT)) {
            return $int;
        }

        return null;
    }
}
