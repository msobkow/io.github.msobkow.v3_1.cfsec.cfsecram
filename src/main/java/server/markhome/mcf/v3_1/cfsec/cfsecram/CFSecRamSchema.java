// Description: Java 25 implementation of an in-memory RAM CFSec schema.

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsecram;

import java.lang.reflect.*;
import java.net.*;
import java.sql.*;
import java.text.*;
import java.util.*;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;

import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsecobj.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.buff.*;
import server.markhome.mcf.v3_1.cfsec.cfsecsaxloader.*;

//import server.markhome.mcf.v3_1.cfsec.cfsecpub.buff.CFSecPubBuffFactoryService;

public class CFSecRamSchema
	extends CFSecBuffSchema
	implements ICFSecSchema
{
	protected short nextISOCcyIdGenValue = 1;
	protected short nextISOCtryIdGenValue = 1;
	protected short nextISOLangIdGenValue = 1;
	protected short nextISOTZoneIdGenValue = 1;
	protected int nextTableInfoIdGenValue = 1;


	public CFSecRamSchema() {
		super();
		tableCluster = new CFSecRamClusterTable( this );
		tableISOCcy = new CFSecRamISOCcyTable( this );
		tableISOCtry = new CFSecRamISOCtryTable( this );
		tableISOCtryCcy = new CFSecRamISOCtryCcyTable( this );
		tableISOCtryLang = new CFSecRamISOCtryLangTable( this );
		tableISOLang = new CFSecRamISOLangTable( this );
		tableISOTZone = new CFSecRamISOTZoneTable( this );
		tableSecClusGrp = new CFSecRamSecClusGrpTable( this );
		tableSecClusGrpMemb = new CFSecRamSecClusGrpMembTable( this );
		tableSecClusRole = new CFSecRamSecClusRoleTable( this );
		tableSecClusRoleMemb = new CFSecRamSecClusRoleMembTable( this );
		tableSecSession = new CFSecRamSecSessionTable( this );
		tableSecSysGrp = new CFSecRamSecSysGrpTable( this );
		tableSecSysGrpInc = new CFSecRamSecSysGrpIncTable( this );
		tableSecSysGrpMemb = new CFSecRamSecSysGrpMembTable( this );
		tableSecSysRole = new CFSecRamSecSysRoleTable( this );
		tableSecSysRoleEnables = new CFSecRamSecSysRoleEnablesTable( this );
		tableSecSysRoleMemb = new CFSecRamSecSysRoleMembTable( this );
		tableSecTentGrp = new CFSecRamSecTentGrpTable( this );
		tableSecTentGrpMemb = new CFSecRamSecTentGrpMembTable( this );
		tableSecTentRole = new CFSecRamSecTentRoleTable( this );
		tableSecTentRoleMemb = new CFSecRamSecTentRoleMembTable( this );
		tableSecUser = new CFSecRamSecUserTable( this );
		tableSecUserEMConf = new CFSecRamSecUserEMConfTable( this );
		tableSecUserPWHistory = new CFSecRamSecUserPWHistoryTable( this );
		tableSecUserPWReset = new CFSecRamSecUserPWResetTable( this );
		tableSecUserPassword = new CFSecRamSecUserPasswordTable( this );
		tableSysCluster = new CFSecRamSysClusterTable( this );
		tableTableInfo = new CFSecRamTableInfoTable( this );
		tableTenant = new CFSecRamTenantTable( this );
	}

	@Override
	public ICFSecSchema newSchema() {
		throw new CFLibMustOverrideException( getClass(), "newSchema" );
	}

	@Override
	public short nextISOCcyIdGen() {
		short next = nextISOCcyIdGenValue++;
		return( next );
	}

	@Override
	public short nextISOCtryIdGen() {
		short next = nextISOCtryIdGenValue++;
		return( next );
	}

	@Override
	public short nextISOLangIdGen() {
		short next = nextISOLangIdGenValue++;
		return( next );
	}

	@Override
	public short nextISOTZoneIdGen() {
		short next = nextISOTZoneIdGenValue++;
		return( next );
	}

	@Override
	public int nextTableInfoIdGen() {
		int next = nextTableInfoIdGenValue++;
		return( next );
	}

	@Override
	public CFLibDbKeyHash256 nextClusterIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextSecSessionIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextSecUserIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextTenantIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextSecSysGrpIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextSecClusGrpIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextSecClusRoleIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextSecTentGrpIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextSecTentRoleIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	public String fileImport( CFSecAuthorization Authorization,
		String fileName,
		String fileContent )
	{
		final String S_ProcName = "fileImport";
		if( ( fileName == null ) || ( fileName.length() <= 0 ) ) {
			throw new CFLibNullArgumentException( getClass(),
				S_ProcName,
				1,
				"fileName" );
		}
		if( ( fileContent == null ) || ( fileContent.length() <= 0 ) ) {
			throw new CFLibNullArgumentException( getClass(),
				S_ProcName,
				2,
				"fileContent" );
		}

		CFSecSaxLoader saxLoader = new CFSecSaxLoader();
		ICFSecSchemaObj schemaObj = new CFSecSchemaObj();
		schemaObj.setCFSecBackingStore( this );
		saxLoader.setSchemaObj( schemaObj );
		ICFSecClusterObj useCluster = schemaObj.getClusterTableObj().readClusterByIdIdx( Authorization.getSecClusterId() );
		ICFSecTenantObj useTenant = schemaObj.getTenantTableObj().readTenantByIdIdx( Authorization.getSecTenantId() );
		CFLibCachedMessageLog runlog = new CFLibCachedMessageLog();
		saxLoader.setLog( runlog );
		saxLoader.setUseCluster( useCluster );
		saxLoader.setUseTenant( useTenant );
		saxLoader.parseStringContents( fileContent );
		String logFileContent = runlog.getCacheContents();
		if( logFileContent == null ) {
			logFileContent = "";
		}

		return( logFileContent );
	}

		
	@Override
	public void wireTableTableInstances() {
		if (tableCluster == null || !(tableCluster instanceof CFSecRamClusterTable)) {
			tableCluster = new CFSecRamClusterTable(this);
		}
		if (tableTenant == null || !(tableTenant instanceof CFSecRamTenantTable)) {
			tableTenant = new CFSecRamTenantTable(this);
		}
		if (tableTableInfo == null || !(tableTableInfo instanceof CFSecRamTableInfoTable)) {
			tableTableInfo = new CFSecRamTableInfoTable(this);
		}
		if (tableISOCcy == null || !(tableISOCcy instanceof CFSecRamISOCcyTable)) {
			tableISOCcy = new CFSecRamISOCcyTable(this);
		}
		if (tableISOCtry == null || !(tableISOCtry instanceof CFSecRamISOCtryTable)) {
			tableISOCtry = new CFSecRamISOCtryTable(this);
		}
		if (tableISOCtryCcy == null || !(tableISOCtryCcy instanceof CFSecRamISOCtryCcyTable)) {
			tableISOCtryCcy = new CFSecRamISOCtryCcyTable(this);
		}
		if (tableISOCtryLang == null || !(tableISOCtryLang instanceof CFSecRamISOCtryLangTable)) {
			tableISOCtryLang = new CFSecRamISOCtryLangTable(this);
		}
		if (tableISOLang == null || !(tableISOLang instanceof CFSecRamISOLangTable)) {
			tableISOLang = new CFSecRamISOLangTable(this);
		}
		if (tableISOTZone == null || !(tableISOTZone instanceof CFSecRamISOTZoneTable)) {
			tableISOTZone = new CFSecRamISOTZoneTable(this);
		}
		if (tableSecUser == null || !(tableSecUser instanceof CFSecRamSecUserTable)) {
			tableSecUser = new CFSecRamSecUserTable(this);
		}
		if (tableSecUserPassword == null || !(tableSecUserPassword instanceof CFSecRamSecUserPasswordTable)) {
			tableSecUserPassword = new CFSecRamSecUserPasswordTable(this);
		}
		if (tableSecUserEMConf == null || !(tableSecUserEMConf instanceof CFSecRamSecUserEMConfTable)) {
			tableSecUserEMConf = new CFSecRamSecUserEMConfTable(this);
		}
		if (tableSecUserPWReset == null || !(tableSecUserPWReset instanceof CFSecRamSecUserPWResetTable)) {
			tableSecUserPWReset = new CFSecRamSecUserPWResetTable(this);
		}
		if (tableSecUserPWHistory == null || !(tableSecUserPWHistory instanceof CFSecRamSecUserPWHistoryTable)) {
			tableSecUserPWHistory = new CFSecRamSecUserPWHistoryTable(this);
		}
		if (tableSecSysGrp == null || !(tableSecSysGrp instanceof CFSecRamSecSysGrpTable)) {
			tableSecSysGrp = new CFSecRamSecSysGrpTable(this);
		}
		if (tableSecSysGrpInc == null || !(tableSecSysGrpInc instanceof CFSecRamSecSysGrpIncTable)) {
			tableSecSysGrpInc = new CFSecRamSecSysGrpIncTable(this);
		}
		if (tableSecSysGrpMemb == null || !(tableSecSysGrpMemb instanceof CFSecRamSecSysGrpMembTable)) {
			tableSecSysGrpMemb = new CFSecRamSecSysGrpMembTable(this);
		}
		if (tableSecClusGrp == null || !(tableSecClusGrp instanceof CFSecRamSecClusGrpTable)) {
			tableSecClusGrp = new CFSecRamSecClusGrpTable(this);
		}
		if (tableSecClusGrpMemb == null || !(tableSecClusGrpMemb instanceof CFSecRamSecClusGrpMembTable)) {
			tableSecClusGrpMemb = new CFSecRamSecClusGrpMembTable(this);
		}
		if (tableSecTentGrp == null || !(tableSecTentGrp instanceof CFSecRamSecTentGrpTable)) {
			tableSecTentGrp = new CFSecRamSecTentGrpTable(this);
		}
		if (tableSecTentGrpMemb == null || !(tableSecTentGrpMemb instanceof CFSecRamSecTentGrpMembTable)) {
			tableSecTentGrpMemb = new CFSecRamSecTentGrpMembTable(this);
		}
		if (tableSecSysRole == null || !(tableSecSysRole instanceof CFSecRamSecSysRoleTable)) {
			tableSecSysRole = new CFSecRamSecSysRoleTable(this);
		}
		if (tableSecSysRoleEnables == null || !(tableSecSysRoleEnables instanceof CFSecRamSecSysRoleEnablesTable)) {
			tableSecSysRoleEnables = new CFSecRamSecSysRoleEnablesTable(this);
		}
		if (tableSecSysRoleMemb == null || !(tableSecSysRoleMemb instanceof CFSecRamSecSysRoleMembTable)) {
			tableSecSysRoleMemb = new CFSecRamSecSysRoleMembTable(this);
		}
		if (tableSecClusRole == null || !(tableSecClusRole instanceof CFSecRamSecClusRoleTable)) {
			tableSecClusRole = new CFSecRamSecClusRoleTable(this);
		}
		if (tableSecClusRoleMemb == null || !(tableSecClusRoleMemb instanceof CFSecRamSecClusRoleMembTable)) {
			tableSecClusRoleMemb = new CFSecRamSecClusRoleMembTable(this);
		}
		if (tableSecTentRole == null || !(tableSecTentRole instanceof CFSecRamSecTentRoleTable)) {
			tableSecTentRole = new CFSecRamSecTentRoleTable(this);
		}
		if (tableSecTentRoleMemb == null || !(tableSecTentRoleMemb instanceof CFSecRamSecTentRoleMembTable)) {
			tableSecTentRoleMemb = new CFSecRamSecTentRoleMembTable(this);
		}
		if (tableSecSession == null || !(tableSecSession instanceof CFSecRamSecSessionTable)) {
			tableSecSession = new CFSecRamSecSessionTable(this);
		}
		if (tableSysCluster == null || !(tableSysCluster instanceof CFSecRamSysClusterTable)) {
			tableSysCluster = new CFSecRamSysClusterTable(this);
		}
	}
}
