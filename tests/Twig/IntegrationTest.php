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

namespace Nelmio\SecurityBundle\Tests\Twig;

use Nelmio\SecurityBundle\ContentSecurityPolicy\DirectiveSet;
use Nelmio\SecurityBundle\ContentSecurityPolicy\DirectiveSetBuilderInterface;
use Nelmio\SecurityBundle\ContentSecurityPolicy\NonceGeneratorInterface;
use Nelmio\SecurityBundle\ContentSecurityPolicy\PolicyManager;
use Nelmio\SecurityBundle\ContentSecurityPolicy\ShaComputer;
use Nelmio\SecurityBundle\ContentSecurityPolicy\ShaComputerInterface;
use Nelmio\SecurityBundle\EventListener\ContentSecurityPolicyListener;
use Nelmio\SecurityBundle\Twig\CSPRuntime;
use Nelmio\SecurityBundle\Twig\NelmioCSPTwigExtension;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Twig\Environment;
use Twig\Loader\ArrayLoader;
use Twig\Loader\FilesystemLoader;
use Twig\Loader\LoaderInterface;
use Twig\RuntimeLoader\RuntimeLoaderInterface;

class IntegrationTest extends TestCase
{
    public function testItWorksDynamically(): void
    {
        $shaComputer = $this->getMockBuilder(ShaComputerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $shaComputer->expects($this->once())
            ->method('computeForScript')
            ->willReturn('sha-script');
        $shaComputer->expects($this->once())
            ->method('computeForStyle')
            ->willReturn('sha-style');

        $policyManager = new PolicyManager();

        $listener = new ContentSecurityPolicyListener(
            $this->createDirectiveSetBuilderMock(new DirectiveSet($policyManager)),
            $this->createDirectiveSetBuilderMock(new DirectiveSet($policyManager)),
            $this->createStub(NonceGeneratorInterface::class),
            $shaComputer
        );

        $cspRuntime = new CSPRuntime($listener);

        $twig = new Environment(new FilesystemLoader(__DIR__.'/templates'));
        $twig->addExtension(new NelmioCSPTwigExtension($shaComputer));
        $loader = $this->createMock(RuntimeLoaderInterface::class);
        $loader->method('load')->willReturnMap([
            [CSPRuntime::class, $cspRuntime],
        ]);
        $twig->addRuntimeLoader($loader);

        $listener->onKernelRequest(new RequestEvent(
            $this->createStub(HttpKernelInterface::class),
            Request::create('/'),
            HttpKernelInterface::MAIN_REQUEST
        ));

        $this->assertSame('<script type="text/javascript">console.log(\'123456\');</script>

<style type="text/css">body{ background: black; }</style>
', $twig->render('test-dynamic.twig', ['api_key' => '123456', 'color' => 'black']));

        $getSha = \Closure::bind(static function (ContentSecurityPolicyListener $listener): ?array {
            return $listener->sha;
        }, null, ContentSecurityPolicyListener::class);

        $this->assertSame(['script-src' => ['sha-script'], 'style-src' => ['sha-style']], $getSha($listener));
    }

    public function testItWorksStatically(): void
    {
        $shaComputer = $this->getMockBuilder(ShaComputerInterface::class)
            ->disableOriginalConstructor()
            ->getMock();
        $shaComputer->expects($this->once())
            ->method('computeForScript')
            ->willReturn('sha-script');
        $shaComputer->expects($this->once())
            ->method('computeForStyle')
            ->willReturn('sha-style');

        $policyManager = new PolicyManager();

        $listener = new ContentSecurityPolicyListener(
            $this->createDirectiveSetBuilderMock(new DirectiveSet($policyManager)),
            $this->createDirectiveSetBuilderMock(new DirectiveSet($policyManager)),
            $this->createStub(NonceGeneratorInterface::class),
            $shaComputer
        );

        $cspRuntime = new CSPRuntime($listener);

        $twig = new Environment(new FilesystemLoader(__DIR__.'/templates'));
        $twig->addExtension(new NelmioCSPTwigExtension($shaComputer));
        $loader = $this->createMock(RuntimeLoaderInterface::class);
        $loader->method('load')->willReturnMap([
            [CSPRuntime::class, $cspRuntime],
        ]);
        $twig->addRuntimeLoader($loader);

        $listener->onKernelRequest(new RequestEvent(
            $this->createStub(HttpKernelInterface::class),
            Request::create('/'),
            HttpKernelInterface::MAIN_REQUEST
        ));

        $this->assertSame('<script type="text/javascript">console.log(\'Hello\');</script>

<style type="text/css">body{ background: red; }</style>
', $twig->render('test-static.twig'));

        $getSha = \Closure::bind(static function (ContentSecurityPolicyListener $listener): ?array {
            return $listener->sha;
        }, null, ContentSecurityPolicyListener::class);

        $this->assertSame(['script-src' => ['sha-script'], 'style-src' => ['sha-style']], $getSha($listener));
    }

    /**
     * @dataProvider provideTemplatesWithSeveralTags
     *
     * @param list<string> $expectedScripts
     * @param list<string> $expectedStyles
     */
    public function testItHashesEachInlineTagOfABlock(string $template, array $expectedScripts, array $expectedStyles): void
    {
        $shaComputer = new ShaComputer('sha256');
        $listener = $this->createListener($shaComputer);
        $twig = $this->createTwig($shaComputer, $listener);

        $twig->render($template, ['entrypoint' => 'app', 'color' => 'red']);

        $this->assertSame([
            'script-src' => array_map([$shaComputer, 'computeForScript'], $expectedScripts),
            'style-src' => array_map([$shaComputer, 'computeForStyle'], $expectedStyles),
        ], $this->getSha($listener));
    }

    public static function provideTemplatesWithSeveralTags(): iterable
    {
        $severalScripts = ['<script type="importmap">{"imports":{"app":"/assets/app.js"}}</script>', '<script type="module">import \'app\';</script>'];
        $severalStyles = ['<style>body{ background: red; }</style>', '<style>p{ color: red; }</style>'];

        yield 'static block' => ['test-several-tags-static.twig', $severalScripts, $severalStyles];
        yield 'dynamic block' => ['test-several-tags-dynamic.twig', $severalScripts, $severalStyles];
        yield 'static block with one inline tag' => [
            'test-one-inline-tag-static.twig',
            ['<script type="module">import \'app\';</script>'],
            ['<style>body{ background: red; }</style>'],
        ];
    }

    public function testItHashesStaticBlocksOfSeveralTagsOnlyAtCompileTime(): void
    {
        $shaComputer = $this->createMock(ShaComputerInterface::class);
        $shaComputer->expects($this->exactly(2))
            ->method('computeForScript')
            ->willReturn('sha-script');
        $shaComputer->expects($this->exactly(2))
            ->method('computeForStyle')
            ->willReturn('sha-style');

        $listener = $this->createListener($shaComputer);
        $twig = $this->createTwig($shaComputer, $listener, new ArrayLoader([
            'compiled-once.twig' => (string) file_get_contents(__DIR__.'/templates/test-several-tags-static.twig'),
        ]));

        $twig->render('compiled-once.twig');
        $twig->render('compiled-once.twig');

        $this->assertSame([
            'script-src' => ['sha-script', 'sha-script', 'sha-script', 'sha-script'],
            'style-src' => ['sha-style', 'sha-style', 'sha-style', 'sha-style'],
        ], $this->getSha($listener));
    }

    public function testItCompilesAHashThatNeedsEscaping(): void
    {
        $hash = 'sha256-it\'s "$x" \\';
        $shaComputer = $this->createStub(ShaComputerInterface::class);
        $shaComputer->method('computeForScript')->willReturn($hash);

        $listener = $this->createListener($shaComputer);
        $twig = $this->createTwig($shaComputer, $listener, new ArrayLoader([
            'escaped-hash.twig' => '{% cspscript %}<script>first();</script>{% endcspscript %}',
        ]));

        $twig->render('escaped-hash.twig');

        $this->assertSame([$hash], $this->getSha($listener)['script-src'] ?? null);
    }

    private function createListener(ShaComputerInterface $shaComputer): ContentSecurityPolicyListener
    {
        $policyManager = new PolicyManager();

        $listener = new ContentSecurityPolicyListener(
            $this->createDirectiveSetBuilderMock(new DirectiveSet($policyManager)),
            $this->createDirectiveSetBuilderMock(new DirectiveSet($policyManager)),
            $this->createStub(NonceGeneratorInterface::class),
            $shaComputer
        );

        $listener->onKernelRequest(new RequestEvent(
            $this->createStub(HttpKernelInterface::class),
            Request::create('/'),
            HttpKernelInterface::MAIN_REQUEST
        ));

        return $listener;
    }

    private function createTwig(ShaComputerInterface $shaComputer, ContentSecurityPolicyListener $listener, ?LoaderInterface $templateLoader = null): Environment
    {
        $twig = new Environment($templateLoader ?? new FilesystemLoader(__DIR__.'/templates'));
        $twig->addExtension(new NelmioCSPTwigExtension($shaComputer));
        $loader = $this->createMock(RuntimeLoaderInterface::class);
        $loader->method('load')->willReturnMap([
            [CSPRuntime::class, new CSPRuntime($listener)],
        ]);
        $twig->addRuntimeLoader($loader);

        return $twig;
    }

    /**
     * @return array<string, list<string>>|null
     */
    private function getSha(ContentSecurityPolicyListener $listener): ?array
    {
        $getSha = \Closure::bind(static function (ContentSecurityPolicyListener $listener): ?array {
            return $listener->sha;
        }, null, ContentSecurityPolicyListener::class);

        return $getSha($listener);
    }

    private function createDirectiveSetBuilderMock(DirectiveSet $directiveSet): DirectiveSetBuilderInterface
    {
        $mock = $this->createMock(DirectiveSetBuilderInterface::class);
        $mock->method('buildDirectiveSet')->willReturn($directiveSet);

        return $mock;
    }
}
