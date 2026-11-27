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

namespace Nelmio\SecurityBundle\Tests\PhpUnit;

use PHPUnit\Event\Facade as EventFacade;
use PHPUnit\Event\Test\DeprecationTriggered;
use PHPUnit\Event\Test\DeprecationTriggeredSubscriber;

final class SelfDeprecationSubscriber implements DeprecationTriggeredSubscriber
{
    private const DEPRECATION_CONTRACTS_PREFIX = 'Since nelmio/security-bundle ';

    public function notify(DeprecationTriggered $event): void
    {
        if ($event->ignoredByTest() || !str_starts_with($event->message(), self::DEPRECATION_CONTRACTS_PREFIX)) {
            return;
        }

        EventFacade::emitter()->testRunnerTriggeredPhpunitWarning(\sprintf(
            '%s triggered a nelmio/security-bundle deprecation without #[IgnoreDeprecations]: %s',
            $event->test()->id(),
            $event->message()
        ));
    }
}
