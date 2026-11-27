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

namespace Nelmio\SecurityBundle\ContentSecurityPolicy;

use Dom\Comment;
use Dom\Element;
use Dom\HTMLDocument;
use Dom\Text;

/**
 * @internal
 */
final class InlineElementExtractor
{
    private const END_OF_BLOCK_MARKER = 'nelmio-security-end-of-block';
    private const HTML_NAMESPACE = 'http://www.w3.org/1999/xhtml';
    private const HTML_WHITESPACE = " \t\n\f\r";
    private const EXTERNAL_FILE_TAG_NAMES = ['style' => 'link'];

    /**
     * @return list<string>
     */
    public static function extractInlineElements(string $html, string $elementName): array
    {
        [$document, $body] = self::parseBlock($html, $elementName);

        $singleElement = self::findSingleElement($body, $elementName);
        if (null !== $singleElement && !self::loadsExternalFile($singleElement)) {
            return [$html];
        }

        $elements = self::findElements($document, $body, $elementName);
        if ([] === $elements && !self::holdsExternalFileTag($body, $elementName)) {
            throw new \InvalidArgumentException(\sprintf('Invalid %1$s, the block holds no <%1$s> tag.', $elementName));
        }

        $inlineElements = [];
        foreach ($elements as [$elementDocument, $element]) {
            if (!self::loadsExternalFile($element) && null === $element->parentElement?->closest('noscript')) {
                $inlineElements[] = $elementDocument->saveHtml($element);
            }
        }

        return $inlineElements;
    }

    public static function extractSingleElementContent(string $html, string $elementName): string
    {
        [, $body] = self::parseBlock($html, $elementName);
        $element = self::findSingleElement($body, $elementName);

        if (null === $element) {
            throw new \InvalidArgumentException(\sprintf('Invalid %1$s, you should use a single <%1$s> tag.', $elementName));
        }

        return $element->textContent ?? '';
    }

    /**
     * @return array{HTMLDocument, Element}
     */
    private static function parseBlock(string $html, string $elementName): array
    {
        $document = HTMLDocument::createFromString(
            \sprintf('<!DOCTYPE html><body>%s<!--%s-->', $html, self::END_OF_BLOCK_MARKER),
            \LIBXML_NOERROR,
            'UTF-8',
        );

        $lastNode = $document;
        while (null !== $lastNode->lastChild) {
            $lastNode = $lastNode->lastChild;
        }

        $body = $document->body;
        if (null === $body || !$lastNode instanceof Comment || self::END_OF_BLOCK_MARKER !== $lastNode->data) {
            throw new \InvalidArgumentException(\sprintf('Invalid %1$s, a tag of the block is not closed.', $elementName));
        }

        $lastNode->remove();

        return [$document, $body];
    }

    private static function findSingleElement(Element $body, string $elementName): ?Element
    {
        $singleElement = null;
        foreach ($body->childNodes as $node) {
            if ($node instanceof Text && '' === trim($node->data, self::HTML_WHITESPACE)) {
                continue;
            }

            if (null !== $singleElement || !$node instanceof Element || $elementName !== $node->localName) {
                return null;
            }

            $singleElement = $node;
        }

        return $singleElement;
    }

    /**
     * @return list<array{HTMLDocument, Element}>
     */
    private static function findElements(HTMLDocument $document, Element $root, string $elementName): array
    {
        $elements = [];
        foreach ($root->getElementsByTagName($elementName) as $element) {
            if (self::HTML_NAMESPACE !== $element->namespaceURI) {
                throw new \InvalidArgumentException(\sprintf('Invalid %1$s, a <%1$s> tag inside <svg> or <math> cannot be hashed.', $elementName));
            }

            $elements[] = [$document, $element];
        }

        foreach ($root->getElementsByTagName('template') as $template) {
            [$templateDocument, $templateBody] = self::parseBlock($template->innerHTML, $elementName);
            array_push($elements, ...self::findElements($templateDocument, $templateBody, $elementName));
        }

        return $elements;
    }

    private static function holdsExternalFileTag(Element $body, string $elementName): bool
    {
        return isset(self::EXTERNAL_FILE_TAG_NAMES[$elementName])
            && null !== $body->querySelector(self::EXTERNAL_FILE_TAG_NAMES[$elementName]);
    }

    private static function loadsExternalFile(Element $element): bool
    {
        return 'script' === $element->localName && $element->hasAttribute('src');
    }
}
