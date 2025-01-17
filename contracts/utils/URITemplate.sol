// SPDX-License-Identifier: Unlicense
pragma solidity ^0.8.4;

/**
 * @dev Helper contract for constructing token URIs where the tokenId may not
 * be at the end of the token URI, e.g., "https://foo.xyz/{id}?bar=baz".
 *
 * This is especially useful when driving token metadata from a Tableland query
 * where tokenId may be embedded in the middle of the query string.
 */
contract URITemplate {
    // URI components used to build token URIs.
    string[] private _uriParts;

    /**
     * @dev Sets the URI template.
     *
     * uriTemplate - an array of uri component strings (each component will be joined with `tokenId` to produce a token URI)
     */
    function _setURITemplate(string[] memory uriTemplate) internal {
        _uriParts = uriTemplate;
    }

    /**
     * @dev Returns a token URI based on the set template string.
     *
     * tokenIdStr - the `tokenId` as a string
     */
    function _getTokenURI(
        string memory tokenIdStr
    ) internal view returns (string memory) {
        // Return an empty string if no URI parts exist
        if (_uriParts.length == 0) {
            return "";
        }
        // Return a string with `tokenId` at the end if only one URI part exists
        if (_uriParts.length == 1) {
            return string(abi.encodePacked(_uriParts[0], tokenIdStr));
        }

        // Return a string with `tokenId` in between each value of `_uriParts`
        bytes memory uri;
        for (uint256 i = 0; i < _uriParts.length; i++) {
            if (i == 0) {
                uri = abi.encodePacked(_uriParts[i]);
            } else {
                uri = abi.encodePacked(uri, tokenIdStr, _uriParts[i]);
            }
        }

        return string(uri);
    }
}
