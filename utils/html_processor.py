#!/usr/bin/env python3
"""
HTML Processing Module

Preprocesses HTML content for SimHash calculation and text extraction.

Usage:
    processor = HTMLProcessor()
    text = processor.preprocess(html)
    tokens = processor.tokenize(text)
"""

import re
import warnings
from typing import List

try:
    from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning, MarkupResemblesLocatorWarning
except ImportError:
    raise ImportError("BeautifulSoup4 is required. Install with: pip install beautifulsoup4")


class HTMLProcessor:
    """HTML content processor for text extraction and tokenization."""

    # Common noise words to filter out
    NOISE_WORDS = {
        'html', 'body', 'head', 'div', 'span', 'class', 'id', 'style', 'script',
        'www', 'http', 'https', 'com', 'net', 'org', 'DOCTYPE', 'type', 'text',
        'javascript', 'function', 'var', 'return', 'if', 'else', 'width', 'height',
        'px', 'border', 'margin', 'padding', 'display', 'none', 'block', 'inline',
        'position', 'relative', 'absolute', 'left', 'right', 'top', 'bottom', 'align',
        'center', 'link', 'meta', 'charset', 'title', 'content', 'name', 'href',
        'src', 'alt', 'img', 'nbsp', 'iframe', 'frame', 'frameset', 'html5',
        'webkit', 'moz', 'ms', 'transition', 'transform', 'animation',
    }

    def __init__(self, filter_noise: bool = True, min_word_length: int = 2):
        """
        Initialize HTML processor.

        Args:
            filter_noise: Whether to filter out noise words
            min_word_length: Minimum word length to keep
        """
        self.filter_noise = filter_noise
        self.min_word_length = min_word_length

        # Suppress BeautifulSoup warnings
        warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
        warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

    def preprocess(self, html: str) -> str:
        """
        Preprocess HTML content for text extraction.

        Removes script/style tags, extracts visible text, converts to lowercase.

        Args:
            html: Raw HTML content

        Returns:
            Preprocessed text string
        """
        if not html:
            return ""

        try:
            soup = BeautifulSoup(html, 'html.parser')

            # Remove script, style, and noscript elements
            for tag in soup(['script', 'style', 'noscript']):
                tag.decompose()

            # Get text content
            text = soup.get_text(separator=' ', strip=True)

            # Convert to lowercase
            text = text.lower()

            return text

        except Exception:
            return ""

    def tokenize(self, text: str) -> List[str]:
        """
        Tokenize text by non-alphanumeric characters.

        Args:
            text: Input text string

        Returns:
            List of tokens
        """
        if not text:
            return []

        # Split by non-alphanumeric characters
        tokens = re.split(r'\W+', text)

        # Filter out empty strings and short words
        tokens = [t for t in tokens if len(t) >= self.min_word_length]

        # Optionally filter noise words
        if self.filter_noise:
            tokens = [t for t in tokens if t.lower() not in self.NOISE_WORDS]

        return tokens

    def extract_text(self, html: str) -> str:
        """
        Extract clean text from HTML (preprocess + tokenize).

        Args:
            html: Raw HTML content

        Returns:
            Clean text string (tokens rejoined with spaces)
        """
        preprocessed = self.preprocess(html)
        tokens = self.tokenize(preprocessed)
        return ' '.join(tokens)

    def extract_keywords(self, texts: List[str], top_n: int = 10,
                         min_count: int = 2) -> List[tuple]:
        """
        Extract top keywords from a list of texts.

        Args:
            texts: List of preprocessed text strings
            top_n: Number of top keywords to return
            min_count: Minimum occurrence count for a keyword

        Returns:
            List of (keyword, count) tuples sorted by frequency
        """
        from collections import Counter

        # Combine all texts
        combined = ' '.join(texts)
        tokens = self.tokenize(combined)

        # Count word frequencies
        word_count = Counter(tokens)

        # Filter by minimum count
        filtered = {word: count for word, count in word_count.items()
                   if count >= min_count}

        # Get top N
        top_keywords = sorted(filtered.items(), key=lambda x: x[1], reverse=True)[:top_n]

        return top_keywords


# Convenience function for quick text extraction
def extract_text_from_html(html: str, filter_noise: bool = True) -> str:
    """
    Quick text extraction from HTML.

    Args:
        html: Raw HTML content
        filter_noise: Whether to filter noise words

    Returns:
        Clean text string
    """
    processor = HTMLProcessor(filter_noise=filter_noise)
    return processor.extract_text(html)
