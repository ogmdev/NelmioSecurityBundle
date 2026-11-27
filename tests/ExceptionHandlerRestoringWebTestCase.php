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

namespace Nelmio\SecurityBundle\Tests;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

abstract class ExceptionHandlerRestoringWebTestCase extends WebTestCase
{
    /**
     * @var callable|null
     */
    private $exceptionHandlerBeforeTest;

    protected function setUp(): void
    {
        parent::setUp();

        $this->exceptionHandlerBeforeTest = self::currentExceptionHandler();
    }

    protected function tearDown(): void
    {
        parent::tearDown();

        while (null !== self::currentExceptionHandler() && self::currentExceptionHandler() !== $this->exceptionHandlerBeforeTest) {
            restore_exception_handler();
        }
    }

    private static function currentExceptionHandler(): ?callable
    {
        $handler = set_exception_handler(null);
        restore_exception_handler();

        return $handler;
    }
}
