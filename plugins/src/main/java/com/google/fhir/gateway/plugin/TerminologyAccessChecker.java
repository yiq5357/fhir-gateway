/*
 * Copyright 2024 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.fhir.gateway.plugin;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.rest.api.RequestTypeEnum;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableSet;
import com.google.fhir.gateway.FhirUtil;
import com.google.fhir.gateway.HttpFhirClient;
import com.google.fhir.gateway.JwtUtil;
import com.google.fhir.gateway.interfaces.AccessChecker;
import com.google.fhir.gateway.interfaces.AccessCheckerFactory;
import com.google.fhir.gateway.interfaces.AccessDecision;
import com.google.fhir.gateway.interfaces.NoOpAccessDecision;
import com.google.fhir.gateway.interfaces.PatientFinder;
import com.google.fhir.gateway.interfaces.RequestDetailsReader;
import com.google.fhir.gateway.plugin.SmartFhirScope.Permission;
import com.google.fhir.gateway.plugin.SmartFhirScope.Principal;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Set;
import javax.inject.Named;
import org.hl7.fhir.instance.model.api.IIdType;
import org.hl7.fhir.r4.model.Bundle;
import org.hl7.fhir.r4.model.Bundle.BundleEntryComponent;
import org.hl7.fhir.r4.model.Bundle.BundleEntryRequestComponent;
import org.hl7.fhir.r4.model.Reference;
import org.hl7.fhir.r4.model.ResourceType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This access-checker uses the `scope` claims in the access token to decide whether access to
 * terminology resources should be granted or not. The `scope` claims are expected to be
 * SMART-on-FHIR compliant.
 *
 * <p>Supported resources: CodeSystem, ValueSet, ConceptMap, NamingSystem
 *
 * <p>Supported operations: - CodeSystem: $lookup, $validate-code, $subsumes, $find-matches -
 * ValueSet: $expand, $validate-code - ConceptMap: $translate, $closure
 */
public class TerminologyAccessChecker implements AccessChecker {
  private static final Logger logger = LoggerFactory.getLogger(TerminologyAccessChecker.class);

  private final FhirContext fhirContext;
  private final SmartScopeChecker smartScopeChecker;

  // Set of terminology resources supported by this checker
  private static final Set<String> TERMINOLOGY_RESOURCES =
      ImmutableSet.of(
          ResourceType.CodeSystem.name(),
          ResourceType.ValueSet.name(),
          ResourceType.ConceptMap.name(),
          ResourceType.NamingSystem.name());

  // Map of supported operations by resource type (all treated as READ operations)
  private static final Set<String> CODE_SYSTEM_OPERATIONS =
      ImmutableSet.of("$lookup", "$validate-code", "$subsumes", "$find-matches");

  private static final Set<String> VALUE_SET_OPERATIONS =
      ImmutableSet.of("$expand", "$validate-code");

  private static final Set<String> CONCEPT_MAP_OPERATIONS =
      ImmutableSet.of("$translate", "$closure");

  private TerminologyAccessChecker(FhirContext fhirContext, SmartScopeChecker smartScopeChecker) {
    Preconditions.checkNotNull(fhirContext);
    Preconditions.checkNotNull(smartScopeChecker);
    this.fhirContext = fhirContext;
    this.smartScopeChecker = smartScopeChecker;
  }

  @Override
  public AccessDecision checkAccess(RequestDetailsReader requestDetails) {
    // For a Bundle requestDetails.getResourceName() returns null
    if (requestDetails.getRequestType() == RequestTypeEnum.POST
        && requestDetails.getResourceName() == null) {
      return processBundle(requestDetails);
    }

    // Only proceed if this is a terminology resource
    if (!isTerminologyResource(requestDetails.getResourceName())) {
      return NoOpAccessDecision.accessDenied();
    }

    switch (requestDetails.getRequestType()) {
      case GET:
        return processGet(requestDetails);
      case POST:
        return processPost(requestDetails);
      case PUT:
        return processUpdate(requestDetails);
        // TODO(https://github.com/google/fhir-gateway/issues/88): Support update as create
      case PATCH:
        return processUpdate(requestDetails);
      case DELETE:
        return processDelete(requestDetails);
      default:
        return NoOpAccessDecision.accessDenied();
    }
  }

  private boolean isTerminologyResource(String resourceName) {
    return resourceName != null && TERMINOLOGY_RESOURCES.contains(resourceName);
  }

  private AccessDecision processGet(RequestDetailsReader requestDetails) {
    // Check for operations
    String operation = requestDetails.getOperation();
    if (operation != null) {
      return processOperation(requestDetails);
    }

    // This operation corresponds to the read/vread/history operations on instance
    if (requestDetails.getId() != null) {
      return processRead(requestDetails);
    }
    return processSearch(requestDetails);
  }

  private AccessDecision processOperation(RequestDetailsReader requestDetails) {
    String resourceName = requestDetails.getResourceName();
    String operation = requestDetails.getOperation();

    if (ResourceType.CodeSystem.name().equals(resourceName)) {
      if (CODE_SYSTEM_OPERATIONS.contains(operation)) {
        return new NoOpAccessDecision(
            smartScopeChecker.hasPermission(resourceName, Permission.READ));
      }
    } else if (ResourceType.ValueSet.name().equals(resourceName)) {
      if (VALUE_SET_OPERATIONS.contains(operation)) {
        return new NoOpAccessDecision(
            smartScopeChecker.hasPermission(resourceName, Permission.READ));
      }
    } else if (ResourceType.ConceptMap.name().equals(resourceName)) {
      if (CONCEPT_MAP_OPERATIONS.contains(operation)) {
        return new NoOpAccessDecision(
            smartScopeChecker.hasPermission(resourceName, Permission.READ));
      }
    }

    // Operation not supported
    return NoOpAccessDecision.accessDenied();
  }

  private AccessDecision processPost(RequestDetailsReader requestDetails) {
    // Check if this is an operation
    if (requestDetails.getOperation() != null) {
      return processOperation(requestDetails);
    }

    return processCreate(requestDetails);
  }

  private AccessDecision processRead(RequestDetailsReader requestDetails) {
    return new NoOpAccessDecision(
        smartScopeChecker.hasPermission(requestDetails.getResourceName(), Permission.READ));
  }

  private AccessDecision processSearch(RequestDetailsReader requestDetails) {
    return new NoOpAccessDecision(
        smartScopeChecker.hasPermission(requestDetails.getResourceName(), Permission.SEARCH));
  }

  private AccessDecision processCreate(RequestDetailsReader requestDetails) {
    return new NoOpAccessDecision(
        smartScopeChecker.hasPermission(requestDetails.getResourceName(), Permission.CREATE));
  }

  private AccessDecision processUpdate(RequestDetailsReader requestDetails) {
    return new NoOpAccessDecision(
        smartScopeChecker.hasPermission(requestDetails.getResourceName(), Permission.UPDATE));
  }

  private AccessDecision processDelete(RequestDetailsReader requestDetails) {
    return new NoOpAccessDecision(
        smartScopeChecker.hasPermission(requestDetails.getResourceName(), Permission.DELETE));
  }

  private AccessDecision processBundle(RequestDetailsReader requestDetails) {
    Bundle requestBundle = FhirUtil.parseRequestToBundle(fhirContext, requestDetails);

    for (BundleEntryComponent entryComponent : requestBundle.getEntry()) {
      if (!doesBundleElementHavePermission(entryComponent)) {
        return NoOpAccessDecision.accessDenied();
      }
    }
    return NoOpAccessDecision.accessGranted();
  }

  private boolean doesReferenceElementHavePermission(
      IIdType referenceElement, Permission permission) {
    if (referenceElement.getResourceType() != null && referenceElement.hasIdPart()) {
      String resourceType = referenceElement.getResourceType();
      // Only check permission if it's a terminology resource
      if (TERMINOLOGY_RESOURCES.contains(resourceType)) {
        return smartScopeChecker.hasPermission(resourceType, permission);
      }
      return false;
    } else {
      String resourceType = referenceElement.getValue();
      // Only check permission if it's a terminology resource
      if (TERMINOLOGY_RESOURCES.contains(resourceType)) {
        return smartScopeChecker.hasPermission(resourceType, permission);
      }
      return false;
    }
  }

  private boolean doesBundleElementHavePermission(BundleEntryComponent bundleEntry) {
    if (bundleEntry.getResource() != null) {
      String resourceType = bundleEntry.getResource().getResourceType().name();
      // Only process terminology resources
      if (!TERMINOLOGY_RESOURCES.contains(resourceType)) {
        return false;
      }
    }

    BundleEntryRequestComponent bundleEntryRequest = bundleEntry.getRequest();
    try {
      switch (bundleEntryRequest.getMethod()) {
        case GET:
          if (bundleEntryRequest.getUrl() != null) {
            URI resourceUri = new URI(bundleEntryRequest.getUrl());
            String path = resourceUri.getPath();

            // Check for operations in the URL
            if (path.contains("$")) {
              String resourceType = path.substring(1, path.indexOf("$")).trim();
              String operation = path.substring(path.indexOf("$"));

              if (ResourceType.CodeSystem.name().equals(resourceType)) {
                if (CODE_SYSTEM_OPERATIONS.contains(operation)) {
                  return smartScopeChecker.hasPermission(resourceType, Permission.READ);
                }
              } else if (ResourceType.ValueSet.name().equals(resourceType)) {
                if (VALUE_SET_OPERATIONS.contains(operation)) {
                  return smartScopeChecker.hasPermission(resourceType, Permission.READ);
                }
              } else if (ResourceType.ConceptMap.name().equals(resourceType)) {
                if (CONCEPT_MAP_OPERATIONS.contains(operation)) {
                  return smartScopeChecker.hasPermission(resourceType, Permission.READ);
                }
              }
              return false;
            }

            IIdType referenceElement = new Reference(path).getReferenceElement();
            return doesReferenceElementHavePermission(referenceElement, Permission.READ);
          }
          break;
        case POST:
          if (bundleEntry.getResource() != null) {
            String resourceType = bundleEntry.getResource().getResourceType().name();
            if (TERMINOLOGY_RESOURCES.contains(resourceType)) {
              return smartScopeChecker.hasPermission(resourceType, Permission.CREATE);
            }
          }

          // Check for operations in the URL if this is a POST operation
          if (bundleEntryRequest.getUrl() != null && bundleEntryRequest.getUrl().contains("$")) {
            URI resourceUri = new URI(bundleEntryRequest.getUrl());
            String path = resourceUri.getPath();
            String resourceType = path.substring(1, path.indexOf("$")).trim();
            String operation = path.substring(path.indexOf("$"));

            if (ResourceType.CodeSystem.name().equals(resourceType)) {
              if (CODE_SYSTEM_OPERATIONS.contains(operation)) {
                return smartScopeChecker.hasPermission(resourceType, Permission.READ);
              }
            } else if (ResourceType.ValueSet.name().equals(resourceType)) {
              if (VALUE_SET_OPERATIONS.contains(operation)) {
                return smartScopeChecker.hasPermission(resourceType, Permission.READ);
              }
            } else if (ResourceType.ConceptMap.name().equals(resourceType)) {
              if (CONCEPT_MAP_OPERATIONS.contains(operation)) {
                return smartScopeChecker.hasPermission(resourceType, Permission.READ);
              }
            }
          }

          // TODO(https://github.com/google/fhir-gateway/issues/87): Add support for search in post
          break;
        case PUT:
          if (bundleEntryRequest.getUrl() != null) {
            URI resourceUri = new URI(bundleEntryRequest.getUrl());
            IIdType referenceElement = new Reference(resourceUri.getPath()).getReferenceElement();
            return doesReferenceElementHavePermission(referenceElement, Permission.UPDATE);
          }
          break;
        case PATCH:
          if (bundleEntryRequest.getUrl() != null) {
            URI resourceUri = new URI(bundleEntryRequest.getUrl());
            IIdType referenceElement = new Reference(resourceUri.getPath()).getReferenceElement();
            return doesReferenceElementHavePermission(referenceElement, Permission.UPDATE);
          }
          break;
        case DELETE:
          if (bundleEntryRequest.getUrl() != null) {
            URI resourceUri = new URI(bundleEntryRequest.getUrl());
            IIdType referenceElement = new Reference(resourceUri.getPath()).getReferenceElement();
            return doesReferenceElementHavePermission(referenceElement, Permission.DELETE);
          }
          break;
        default:
          return false;
      }
    } catch (URISyntaxException e) {
      logger.error(
          String.format("Error in parsing bundle request url %s", bundleEntryRequest.getUrl()));
    }
    return false;
  }

  @Named(value = "terminology")
  static class Factory implements AccessCheckerFactory {

    @VisibleForTesting static final String SCOPES_CLAIM = "scope";

    private SmartScopeChecker getSmartFhirPermissionChecker(DecodedJWT jwt) {
      String scopesClaim = JwtUtil.getClaimOrDie(jwt, SCOPES_CLAIM);
      String[] scopes = scopesClaim.strip().split("\\s+");
      return new SmartScopeChecker(
          SmartFhirScope.extractSmartFhirScopesFromTokens(Arrays.asList(scopes)), Principal.SYSTEM);
    }

    public AccessChecker create(
        DecodedJWT jwt,
        HttpFhirClient httpFhirClient,
        FhirContext fhirContext,
        PatientFinder patientFinder) {
      return new TerminologyAccessChecker(fhirContext, getSmartFhirPermissionChecker(jwt));
    }
  }
}
