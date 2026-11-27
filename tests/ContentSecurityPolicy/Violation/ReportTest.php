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

namespace Nelmio\SecurityBundle\Tests\ContentSecurityPolicy\Violation;

use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Exception\InvalidPayloadException;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Exception\MissingCspReportException;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Exception\NoDataException;
use Nelmio\SecurityBundle\ContentSecurityPolicy\Violation\Report;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

class ReportTest extends TestCase
{
    public function testFromRequestWithoutData(): void
    {
        $this->expectException(NoDataException::class);
        $this->expectExceptionMessage('Content-Security-Policy Endpoint called without data');

        Report::fromRequest(new Request());
    }

    public function testFromRequestWithoutReportKey(): void
    {
        $this->expectException(MissingCspReportException::class);
        $this->expectExceptionMessage('Content-Security-Policy Endpoint called without "csp-report" data');

        Report::fromRequest(new Request([], [], [], [], [], [], '{}'));
    }

    public function testFromRequestWithInvalidJSON(): void
    {
        $this->expectException(InvalidPayloadException::class);
        $this->expectExceptionMessage('Content-Security-Policy Endpoint called with invalid JSON data');

        Report::fromRequest(new Request([], [], [], [], [], [], 'yolo'));
    }

    public function testFromRequest(): void
    {
        $data = [
            'blocked-uri' => 'self',
            'effective-directive' => 'script-src',
            'script-sample' => 'try {  for(var lastpass_iter=0; lastpass',
        ];

        $report = Report::fromRequest(new Request([], [], [], [], [], [], json_encode([
            'csp-report' => $data,
        ], \JSON_THROW_ON_ERROR)));

        $this->assertSameReportData($data, $report);
        $this->assertFalse($report->isData());
    }

    /**
     * @dataProvider provideCspReports
     *
     * @param array<mixed>                    $payload
     * @param array<string, int|string|null> $expectedData
     */
    public function testFromRequestKeepsOnlyWellTypedFields(array $payload, array $expectedData): void
    {
        $report = Report::fromRequest(new Request([], [], [], [], [], [], json_encode([
            'csp-report' => $payload,
        ], \JSON_THROW_ON_ERROR)));

        $this->assertSameReportData($expectedData, $report);
    }

    public static function provideCspReports(): iterable
    {
        yield 'directive derived from violated-directive, missing blocked-uri kept as null' => [
            ['violated-directive' => 'script-src https://example.com'],
            ['violated-directive' => 'script-src https://example.com', 'effective-directive' => 'script-src', 'blocked-uri' => null],
        ];

        yield 'non-string violated-directive' => [
            ['document-uri' => 'https://example.com', 'violated-directive' => 123],
            ['document-uri' => 'https://example.com', 'effective-directive' => null, 'blocked-uri' => null],
        ];

        yield 'non-string fields read by getters' => [
            ['document-uri' => 'https://example.com', 'blocked-uri' => ['https://example.com'], 'effective-directive' => 42, 'source-file' => 7],
            ['document-uri' => 'https://example.com', 'effective-directive' => null, 'blocked-uri' => null],
        ];

        yield 'int fields' => [
            ['document-uri' => 'https://example.com', 'status-code' => '200', 'line-number' => 'twelve', 'column-number' => 3.5],
            ['document-uri' => 'https://example.com', 'status-code' => 200, 'effective-directive' => null, 'blocked-uri' => null],
        ];

        yield 'unknown field' => [
            ['document-uri' => 'https://example.com', 'unexpected' => 'value'],
            ['document-uri' => 'https://example.com', 'effective-directive' => null, 'blocked-uri' => null],
        ];
    }

    public function testFromRequestWithoutAnyValidField(): void
    {
        $this->expectException(InvalidPayloadException::class);
        $this->expectExceptionMessage('Content-Security-Policy Endpoint called without any valid "csp-report" field');

        Report::fromRequest(new Request([], [], [], [], [], [], '{"csp-report":{"violated-directive":123}}'));
    }

    public function testConstructorDropsIllTypedFields(): void
    {
        // @phpstan-ignore argument.type
        $report = new Report(['violated-directive' => 123, 'blocked-uri' => ['https://example.com']]);

        $this->assertNull($report->getDirective());
        $this->assertNull($report->getUri());
    }

    public function testSetPropertyRejectsValueOfAnotherType(): void
    {
        $this->expectException(\TypeError::class);
        $this->expectExceptionMessage('Report has no "blocked-uri" property accepting int.');

        // @phpstan-ignore argument.type
        (new Report())->setProperty('blocked-uri', 42);
    }

    /**
     * @param array<string, int|string|null> $expectedData
     */
    private function assertSameReportData(array $expectedData, Report $report): void
    {
        $actualData = $report->getData();
        ksort($expectedData);
        ksort($actualData);

        $this->assertSame($expectedData, $actualData);
    }
}
