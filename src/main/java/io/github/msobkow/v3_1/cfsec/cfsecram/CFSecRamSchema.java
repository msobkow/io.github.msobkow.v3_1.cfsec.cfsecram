// Description: Java 25 implementation of an in-memory RAM CFSec schema.

/*
 *	io.github.msobkow.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	This file is part of Mark's Code Fractal CFSec.
 *	
 *	Mark's Code Fractal CFSec is available under dual commercial license from
 *	Mark Stephen Sobkow, or under the terms of the GNU Library General Public License,
 *	Version 3 or later.
 *	
 *	Mark's Code Fractal CFSec is free software: you can redistribute it and/or
 *	modify it under the terms of the GNU Library General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *	
 *	Mark's Code Fractal CFSec is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU Library General Public License
 *	along with Mark's Code Fractal CFSec.  If not, see <https://www.gnu.org/licenses/>.
 *	
 *	If you wish to modify and use this code without publishing your changes in order to
 *	tie it to proprietary code, please contact Mark Stephen Sobkow
 *	for a commercial license at mark.sobkow@gmail.com
 *	
 */

package io.github.msobkow.v3_1.cfsec.cfsecram;

import java.lang.reflect.*;
import java.net.*;
import java.sql.*;
import java.text.*;
import java.util.*;
import io.github.msobkow.v3_1.cflib.*;
import io.github.msobkow.v3_1.cflib.dbutil.*;

import io.github.msobkow.v3_1.cfsec.cfsec.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;
import io.github.msobkow.v3_1.cfsec.cfsec.buff.*;
import io.github.msobkow.v3_1.cfsec.cfsecsaxloader.*;

public class CFSecRamSchema
	extends CFSecBuffSchema
	implements ICFSecSchema
{
	protected short nextISOCcyIdGenValue = 1;
	protected short nextISOCtryIdGenValue = 1;
	protected short nextISOLangIdGenValue = 1;
	protected short nextISOTZoneIdGenValue = 1;
	protected long nextClusterIdGenValue = 1;


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

	public ICFSecSchema newSchema() {
		throw new CFLibMustOverrideException( getClass(), "newSchema" );
	}

	public short nextISOCcyIdGen() {
		short next = nextISOCcyIdGenValue++;
		return( next );
	}

	public short nextISOCtryIdGen() {
		short next = nextISOCtryIdGenValue++;
		return( next );
	}

	public short nextISOLangIdGen() {
		short next = nextISOLangIdGenValue++;
		return( next );
	}

	public short nextISOTZoneIdGen() {
		short next = nextISOTZoneIdGenValue++;
		return( next );
	}

	public long nextClusterIdGen() {
		long next = nextClusterIdGenValue++;
		return( next );
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
}
