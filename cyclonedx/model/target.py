# This file is part of CycloneDX Python Library
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.

from typing import Any, Optional
from collections.abc import Iterable
import py_serializable as serializable
from sortedcontainers import SortedSet

from .._internal.compare import ComparableTuple as _ComparableTuple
from ..exception.model import MutuallyExclusivePropertiesException, NoPropertiesProvidedException
from .impact_analysis import (
    ImpactAnalysisAffectedStatus,
)

@serializable.serializable_class
class BomTargetVersionRange:
    """
    Class that represents either a version or version range and its affected status.

    `version` and `version_range` are mutually exclusive.

    .. note::
        See the CycloneDX schema: https://cyclonedx.org/docs/1.6/xml/#type_vulnerabilityType
    """

    def __init__(
        self, *,
        version: Optional[str] = None,
        range: Optional[str] = None,
        status: Optional[ImpactAnalysisAffectedStatus] = None,
    ) -> None:
        if not version and not range:
            raise NoPropertiesProvidedException(
                'One of version or range must be provided for BomTargetVersionRange - neither provided.'
            )
        if version and range:
            raise MutuallyExclusivePropertiesException(
                'Either version or range should be provided for BomTargetVersionRange - both provided.'
            )
        self.version = version
        self.range = range
        self.status = status

    @property
    @serializable.xml_sequence(1)
    @serializable.xml_string(serializable.XmlStringSerializationType.NORMALIZED_STRING)
    def version(self) -> Optional[str]:
        """
        A single version of a component or service.
        """
        return self._version

    @version.setter
    def version(self, version: Optional[str]) -> None:
        self._version = version

    @property
    @serializable.xml_sequence(2)
    def range(self) -> Optional[str]:
        """
        A version range specified in Package URL Version Range syntax (vers) which is defined at
        https://github.com/package-url/purl-spec/VERSION-RANGE-SPEC.rst

        .. note::
            The VERSION-RANGE-SPEC from Package URL is not a formalised standard at the time of writing and this no
            validation of conformance with this draft standard is performed.
        """
        return self._range

    @range.setter
    def range(self, range: Optional[str]) -> None:
        self._range = range

    @property
    @serializable.xml_sequence(3)
    def status(self) -> Optional[ImpactAnalysisAffectedStatus]:
        """
        The vulnerability status for the version or range of versions.
        """
        return self._status

    @status.setter
    def status(self, status: Optional[ImpactAnalysisAffectedStatus]) -> None:
        self._status = status

    def __comparable_tuple(self) -> _ComparableTuple:
        return _ComparableTuple((
            self.version, self.range, self.status
        ))

    def __eq__(self, other: object) -> bool:
        if isinstance(other, BomTargetVersionRange):
            return self.__comparable_tuple() == other.__comparable_tuple()
        return False

    def __lt__(self, other: Any) -> bool:
        if isinstance(other, BomTargetVersionRange):
            return self.__comparable_tuple() < other.__comparable_tuple()
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.__comparable_tuple())

    def __repr__(self) -> str:
        return f'<BomTargetVersionRange version={self.version}, version_range={self.range}, status={self.status}>'


@serializable.serializable_class
class BomTarget:
    """
    Class that represents referencing a Component or Service in a BOM.

    Aims to represent the sub-element `target` of the complex type `vulnerabilityType`.

    You can either create a `cyclonedx.model.bom.Bom` yourself programmatically, or generate a `cyclonedx.model.bom.Bom`
    from a `cyclonedx.parser.BaseParser` implementation.

    .. note::
        See the CycloneDX schema: https://cyclonedx.org/docs/1.6/#type_vulnerabilityType
    """

    def __init__(
        self, *,
        ref: str,
        versions: Optional[Iterable[BomTargetVersionRange]] = None,
    ) -> None:
        self.ref = ref
        self.versions = versions or []  # type:ignore[assignment]

    @property
    @serializable.xml_sequence(1)
    def ref(self) -> str:
        """
        Reference to a component or service by the objects `bom-ref`.
        """
        return self._ref

    @ref.setter
    def ref(self, ref: str) -> None:
        self._ref = ref

    @property
    @serializable.xml_array(serializable.XmlArraySerializationType.NESTED, 'version')
    @serializable.xml_sequence(2)
    def versions(self) -> 'SortedSet[BomTargetVersionRange]':
        """
        Zero or more individual versions or range of versions.

        Returns:
            Set of `BomTargetVersionRange`
        """
        return self._versions

    @versions.setter
    def versions(self, versions: Iterable[BomTargetVersionRange]) -> None:
        self._versions = SortedSet(versions)

    def __comparable_tuple(self) -> _ComparableTuple:
        return _ComparableTuple((
            self.ref,
            _ComparableTuple(self.versions)
        ))

    def __eq__(self, other: object) -> bool:
        if isinstance(other, BomTarget):
            return self.__comparable_tuple() == other.__comparable_tuple()
        return False

    def __lt__(self, other: Any) -> bool:
        if isinstance(other, BomTarget):
            return self.__comparable_tuple() < other.__comparable_tuple()
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.__comparable_tuple())

    def __repr__(self) -> str:
        return f'<BomTarget ref={self.ref}>'
