/**
 * Package module type definitions
 */
import type { IAdtObjectState } from '@mcp-abap-adt/interfaces';
export interface ICreatePackageParams {
    package_name: string;
    description?: string;
    super_package: string;
    package_type?: string;
    software_component?: string;
    transport_layer?: string;
    transport_request?: string;
    application_component?: string;
    responsible?: string;
}
export interface IPackageConfig {
    packageName: string;
    superPackage?: string;
    description?: string;
    updatedDescription?: string;
    packageType?: string;
    softwareComponent?: string;
    transportLayer?: string;
    transportRequest?: string;
    applicationComponent?: string;
    responsible?: string;
    onLock?: (lockHandle: string) => void;
}
export interface IPackageState extends IAdtObjectState {
}
//# sourceMappingURL=types.d.ts.map