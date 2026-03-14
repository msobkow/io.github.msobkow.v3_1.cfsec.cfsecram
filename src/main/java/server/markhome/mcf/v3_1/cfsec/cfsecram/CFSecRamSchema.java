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

public class CFSecRamSchema
	extends CFSecBuffSchema
	implements ICFSecSchema
{
	protected short nextISOCcyIdGenValue = 1;
	protected short nextISOCtryIdGenValue = 1;
	protected short nextISOLangIdGenValue = 1;
	protected short nextISOTZoneIdGenValue = 1;


	public CFSecRamSchema() {
		super();
		tableCluster = new CFSecRamClusterTable( this );
		tableHostNode = new CFSecRamHostNodeTable( this );
		tableISOCcy = new CFSecRamISOCcyTable( this );
		tableISOCtry = new CFSecRamISOCtryTable( this );
		tableISOCtryCcy = new CFSecRamISOCtryCcyTable( this );
		tableISOCtryLang = new CFSecRamISOCtryLangTable( this );
		tableISOLang = new CFSecRamISOLangTable( this );
		tableISOTZone = new CFSecRamISOTZoneTable( this );
		tableSecDevice = new CFSecRamSecDeviceTable( this );
		tableSecGroup = new CFSecRamSecGroupTable( this );
		tableSecGrpInc = new CFSecRamSecGrpIncTable( this );
		tableSecGrpMemb = new CFSecRamSecGrpMembTable( this );
		tableSecSession = new CFSecRamSecSessionTable( this );
		tableSecUser = new CFSecRamSecUserTable( this );
		tableService = new CFSecRamServiceTable( this );
		tableServiceType = new CFSecRamServiceTypeTable( this );
		tableSysCluster = new CFSecRamSysClusterTable( this );
		tableTSecGroup = new CFSecRamTSecGroupTable( this );
		tableTSecGrpInc = new CFSecRamTSecGrpIncTable( this );
		tableTSecGrpMemb = new CFSecRamTSecGrpMembTable( this );
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
	public CFLibDbKeyHash256 nextServiceTypeIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextTenantIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextHostNodeIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextSecGroupIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextSecGrpIncIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextSecGrpMembIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextServiceIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextTSecGroupIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextTSecGrpIncIdGen() {
		CFLibDbKeyHash256 retval = new CFLibDbKeyHash256(0);
		return( retval );
	}

	@Override
	public CFLibDbKeyHash256 nextTSecGrpMembIdGen() {
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
		if (tableHostNode == null || !(tableHostNode instanceof CFSecRamHostNodeTable)) {
			tableHostNode = new CFSecRamHostNodeTable(this);
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
		if (tableSecDevice == null || !(tableSecDevice instanceof CFSecRamSecDeviceTable)) {
			tableSecDevice = new CFSecRamSecDeviceTable(this);
		}
		if (tableSecGroup == null || !(tableSecGroup instanceof CFSecRamSecGroupTable)) {
			tableSecGroup = new CFSecRamSecGroupTable(this);
		}
		if (tableSecGrpInc == null || !(tableSecGrpInc instanceof CFSecRamSecGrpIncTable)) {
			tableSecGrpInc = new CFSecRamSecGrpIncTable(this);
		}
		if (tableSecGrpMemb == null || !(tableSecGrpMemb instanceof CFSecRamSecGrpMembTable)) {
			tableSecGrpMemb = new CFSecRamSecGrpMembTable(this);
		}
		if (tableSecSession == null || !(tableSecSession instanceof CFSecRamSecSessionTable)) {
			tableSecSession = new CFSecRamSecSessionTable(this);
		}
		if (tableSecUser == null || !(tableSecUser instanceof CFSecRamSecUserTable)) {
			tableSecUser = new CFSecRamSecUserTable(this);
		}
		if (tableService == null || !(tableService instanceof CFSecRamServiceTable)) {
			tableService = new CFSecRamServiceTable(this);
		}
		if (tableServiceType == null || !(tableServiceType instanceof CFSecRamServiceTypeTable)) {
			tableServiceType = new CFSecRamServiceTypeTable(this);
		}
		if (tableSysCluster == null || !(tableSysCluster instanceof CFSecRamSysClusterTable)) {
			tableSysCluster = new CFSecRamSysClusterTable(this);
		}
		if (tableTenant == null || !(tableTenant instanceof CFSecRamTenantTable)) {
			tableTenant = new CFSecRamTenantTable(this);
		}
		if (tableTSecGroup == null || !(tableTSecGroup instanceof CFSecRamTSecGroupTable)) {
			tableTSecGroup = new CFSecRamTSecGroupTable(this);
		}
		if (tableTSecGrpInc == null || !(tableTSecGrpInc instanceof CFSecRamTSecGrpIncTable)) {
			tableTSecGrpInc = new CFSecRamTSecGrpIncTable(this);
		}
		if (tableTSecGrpMemb == null || !(tableTSecGrpMemb instanceof CFSecRamTSecGrpMembTable)) {
			tableTSecGrpMemb = new CFSecRamTSecGrpMembTable(this);
		}
	}
}
