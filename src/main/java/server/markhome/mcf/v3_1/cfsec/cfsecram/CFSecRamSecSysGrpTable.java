
// Description: Java 25 in-memory RAM DbIO implementation for SecSysGrp.

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

import java.math.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cflib.keyhash.*;

import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.buff.*;
import server.markhome.mcf.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamSecSysGrpTable in-memory RAM DbIO implementation
 *	for SecSysGrp.
 */
public class CFSecRamSecSysGrpTable
	implements ICFSecSecSysGrpTable
{
	private ICFSecSchema schema;
	private Map< $implCommaIJavaOptAtomType$,
				CFSecBuffSecSysGrp > dictByPKey
		= new HashMap< $implCommaIJavaOptAtomType$,
				CFSecBuffSecSysGrp >();
	private Map< CFSecBuffSecSysGrpByUNameIdxKey,
			CFSecBuffSecSysGrp > dictByUNameIdx
		= new HashMap< CFSecBuffSecSysGrpByUNameIdxKey,
			CFSecBuffSecSysGrp >();
	private Map< CFSecBuffSecSysGrpBySecLevelIdxKey,
				Map< $implCommaIJavaOptAtomType$,
					CFSecBuffSecSysGrp >> dictBySecLevelIdx
		= new HashMap< CFSecBuffSecSysGrpBySecLevelIdxKey,
				Map< $implCommaIJavaOptAtomType$,
					CFSecBuffSecSysGrp >>();

	public CFSecRamSecSysGrpTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecSysGrp ensureRec(ICFSecSecSysGrp rec) {
		return (((CFSecBuffSecSysGrpFactoryService)(schema.getCFSecBuffFactory().getFactorySecSysGrp())).ensureRec(rec));
	}

	@Override
	public ICFSecSecSysGrp createSecSysGrp( ICFSecAuthorization Authorization,
		ICFSecSecSysGrp iBuff )
	{
		final String S_ProcName = "createSecSysGrp";
		
		CFSecBuffSecSysGrp Buff = (CFSecBuffSecSysGrp)ensureRec(iBuff);
		$implCommaIJavaOptAtomType$ pkey;
		pkey = schema.nextSecSysGrpIdGen();
		Buff.setRequiredSecSysGrpId( pkey );
		CFSecBuffSecSysGrpByUNameIdxKey keyUNameIdx = (CFSecBuffSecSysGrpByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrp().newByUNameIdxKey();
		keyUNameIdx.setRequiredName( Buff.getRequiredName() );

		CFSecBuffSecSysGrpBySecLevelIdxKey keySecLevelIdx = (CFSecBuffSecSysGrpBySecLevelIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrp().newBySecLevelIdxKey();
		keySecLevelIdx.setRequiredSecLevel( Buff.getRequiredSecLevel() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUNameIdx.containsKey( keyUNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecSysGrpUNameIdx",
				"SecSysGrpUNameIdx",
				keyUNameIdx );
		}

		// Validate foreign keys

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		dictByUNameIdx.put( keyUNameIdx, Buff );

		Map< $implCommaIJavaOptAtomType$, CFSecBuffSecSysGrp > subdictSecLevelIdx;
		if( dictBySecLevelIdx.containsKey( keySecLevelIdx ) ) {
			subdictSecLevelIdx = dictBySecLevelIdx.get( keySecLevelIdx );
		}
		else {
			subdictSecLevelIdx = new HashMap< $implCommaIJavaOptAtomType$, CFSecBuffSecSysGrp >();
			dictBySecLevelIdx.put( keySecLevelIdx, subdictSecLevelIdx );
		}
		subdictSecLevelIdx.put( pkey, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecSysGrp.CLASS_CODE) {
				CFSecBuffSecSysGrp retbuff = ((CFSecBuffSecSysGrp)(schema.getCFSecBuffFactory().getFactorySecSysGrp().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecSysGrp readDerived( ICFSecAuthorization Authorization,
		$implCommaIJavaOptAtomType$ PKey )
	{
		final String S_ProcName = "CFSecRamSecSysGrp.readDerived";
		ICFSecSecSysGrp buff;
		if( PKey == null ) {
			return( null );
		}
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysGrp lockDerived( ICFSecAuthorization Authorization,
		$implCommaIJavaOptAtomType$ PKey )
	{
		final String S_ProcName = "CFSecRamSecSysGrp.lockDerived";
		ICFSecSecSysGrp buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysGrp[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecSysGrp.readAllDerived";
		ICFSecSecSysGrp[] retList = new ICFSecSecSysGrp[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecSysGrp > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecSecSysGrp readDerivedByUNameIdx( ICFSecAuthorization Authorization,
		String Name )
	{
		final String S_ProcName = "CFSecRamSecSysGrp.readDerivedByUNameIdx";
		CFSecBuffSecSysGrpByUNameIdxKey key = (CFSecBuffSecSysGrpByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrp().newByUNameIdxKey();

		key.setRequiredName( Name );
		ICFSecSecSysGrp buff;
		if( dictByUNameIdx.containsKey( key ) ) {
			buff = dictByUNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysGrp[] readDerivedBySecLevelIdx( ICFSecAuthorization Authorization,
		ICFSecPubSchema.SecLevelEnum SecLevel )
	{
		final String S_ProcName = "CFSecRamSecSysGrp.readDerivedBySecLevelIdx";
		CFSecBuffSecSysGrpBySecLevelIdxKey key = (CFSecBuffSecSysGrpBySecLevelIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrp().newBySecLevelIdxKey();

		key.setRequiredSecLevel( SecLevel );
		ICFSecSecSysGrp[] recArray;
		if( dictBySecLevelIdx.containsKey( key ) ) {
			Map< $implCommaIJavaOptAtomType$, CFSecBuffSecSysGrp > subdictSecLevelIdx
				= dictBySecLevelIdx.get( key );
			recArray = new ICFSecSecSysGrp[ subdictSecLevelIdx.size() ];
			Iterator< CFSecBuffSecSysGrp > iter = subdictSecLevelIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< $implCommaIJavaOptAtomType$, CFSecBuffSecSysGrp > subdictSecLevelIdx
				= new HashMap< $implCommaIJavaOptAtomType$, CFSecBuffSecSysGrp >();
			dictBySecLevelIdx.put( key, subdictSecLevelIdx );
			recArray = new ICFSecSecSysGrp[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecSysGrp readDerivedByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecSysGrpId )
	{
		final String S_ProcName = "CFSecRamSecSysGrp.readDerivedByIdIdx() ";
		ICFSecSecSysGrp buff;
		if( dictByPKey.containsKey( SecSysGrpId ) ) {
			buff = dictByPKey.get( SecSysGrpId );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysGrp readRec( ICFSecAuthorization Authorization,
		$implCommaIJavaOptAtomType$ PKey )
	{
		final String S_ProcName = "CFSecRamSecSysGrp.readRec";
		ICFSecSecSysGrp buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecSysGrp.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysGrp lockRec( ICFSecAuthorization Authorization,
		$implCommaIJavaOptAtomType$ PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecSysGrp buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecSysGrp.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysGrp[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecSysGrp.readAllRec";
		ICFSecSecSysGrp buff;
		ArrayList<ICFSecSecSysGrp> filteredList = new ArrayList<ICFSecSecSysGrp>();
		ICFSecSecSysGrp[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSysGrp.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecSysGrp[0] ) );
	}

	@Override
	public ICFSecSecSysGrp readRecByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecSysGrpId )
	{
		final String S_ProcName = "CFSecRamSecSysGrp.readRecByIdIdx() ";
		ICFSecSecSysGrp buff = readDerivedByIdIdx( Authorization,
			SecSysGrpId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSysGrp.CLASS_CODE ) ) {
			return( (ICFSecSecSysGrp)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecSysGrp readRecByUNameIdx( ICFSecAuthorization Authorization,
		String Name )
	{
		final String S_ProcName = "CFSecRamSecSysGrp.readRecByUNameIdx() ";
		ICFSecSecSysGrp buff = readDerivedByUNameIdx( Authorization,
			Name );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSysGrp.CLASS_CODE ) ) {
			return( (ICFSecSecSysGrp)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecSysGrp[] readRecBySecLevelIdx( ICFSecAuthorization Authorization,
		ICFSecPubSchema.SecLevelEnum SecLevel )
	{
		final String S_ProcName = "CFSecRamSecSysGrp.readRecBySecLevelIdx() ";
		ICFSecSecSysGrp buff;
		ArrayList<ICFSecSecSysGrp> filteredList = new ArrayList<ICFSecSecSysGrp>();
		ICFSecSecSysGrp[] buffList = readDerivedBySecLevelIdx( Authorization,
			SecLevel );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSysGrp.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecSysGrp)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecSysGrp[0] ) );
	}

	public ICFSecSecSysGrp updateSecSysGrp( ICFSecAuthorization Authorization,
		ICFSecSecSysGrp iBuff )
	{
		CFSecBuffSecSysGrp Buff = (CFSecBuffSecSysGrp)ensureRec(iBuff);
		$implCommaIJavaOptAtomType$ pkey = ($implCommaIJavaOptAtomType$)Buff.getPKey();
		CFSecBuffSecSysGrp existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecSysGrp",
				"Existing record not found",
				"Existing record not found",
				"SecSysGrp",
				"SecSysGrp",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecSysGrp",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecSysGrpByUNameIdxKey existingKeyUNameIdx = (CFSecBuffSecSysGrpByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrp().newByUNameIdxKey();
		existingKeyUNameIdx.setRequiredName( existing.getRequiredName() );

		CFSecBuffSecSysGrpByUNameIdxKey newKeyUNameIdx = (CFSecBuffSecSysGrpByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrp().newByUNameIdxKey();
		newKeyUNameIdx.setRequiredName( Buff.getRequiredName() );

		CFSecBuffSecSysGrpBySecLevelIdxKey existingKeySecLevelIdx = (CFSecBuffSecSysGrpBySecLevelIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrp().newBySecLevelIdxKey();
		existingKeySecLevelIdx.setRequiredSecLevel( existing.getRequiredSecLevel() );

		CFSecBuffSecSysGrpBySecLevelIdxKey newKeySecLevelIdx = (CFSecBuffSecSysGrpBySecLevelIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrp().newBySecLevelIdxKey();
		newKeySecLevelIdx.setRequiredSecLevel( Buff.getRequiredSecLevel() );

		// Check unique indexes

		if( ! existingKeyUNameIdx.equals( newKeyUNameIdx ) ) {
			if( dictByUNameIdx.containsKey( newKeyUNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecSysGrp",
					"SecSysGrpUNameIdx",
					"SecSysGrpUNameIdx",
					newKeyUNameIdx );
			}
		}

		// Validate foreign keys

		// Update is valid

		Map< $implCommaIJavaOptAtomType$, CFSecBuffSecSysGrp > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		dictByUNameIdx.remove( existingKeyUNameIdx );
		dictByUNameIdx.put( newKeyUNameIdx, Buff );

		subdict = dictBySecLevelIdx.get( existingKeySecLevelIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictBySecLevelIdx.containsKey( newKeySecLevelIdx ) ) {
			subdict = dictBySecLevelIdx.get( newKeySecLevelIdx );
		}
		else {
			subdict = new HashMap< $implCommaIJavaOptAtomType$, CFSecBuffSecSysGrp >();
			dictBySecLevelIdx.put( newKeySecLevelIdx, subdict );
		}
		subdict.put( pkey, Buff );

		return(Buff);
	}

	@Override
	public void deleteSecSysGrp( ICFSecAuthorization Authorization,
		ICFSecSecSysGrp iBuff )
	{
		final String S_ProcName = "CFSecRamSecSysGrpTable.deleteSecSysGrp() ";
		CFSecBuffSecSysGrp Buff = (CFSecBuffSecSysGrp)ensureRec(iBuff);
		int classCode;
		$implCommaIJavaOptAtomType$ pkey = ($implCommaIJavaOptAtomType$)(Buff.getPKey());
		CFSecBuffSecSysGrp existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecSysGrp",
				pkey );
		}
					schema.getTableSecSysGrpMemb().deleteSecSysGrpMembBySysGrpIdx( Authorization,
						existing.getRequiredSecSysGrpId() );
					schema.getTableSecSysGrpInc().deleteSecSysGrpIncBySysGrpIdx( Authorization,
						existing.getRequiredSecSysGrpId() );
		CFSecBuffSecSysGrpByUNameIdxKey keyUNameIdx = (CFSecBuffSecSysGrpByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrp().newByUNameIdxKey();
		keyUNameIdx.setRequiredName( existing.getRequiredName() );

		CFSecBuffSecSysGrpBySecLevelIdxKey keySecLevelIdx = (CFSecBuffSecSysGrpBySecLevelIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrp().newBySecLevelIdxKey();
		keySecLevelIdx.setRequiredSecLevel( existing.getRequiredSecLevel() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< $implCommaIJavaOptAtomType$, CFSecBuffSecSysGrp > subdict;

		dictByPKey.remove( pkey );

		dictByUNameIdx.remove( keyUNameIdx );

		subdict = dictBySecLevelIdx.get( keySecLevelIdx );
		subdict.remove( pkey );

	}
	@Override
	public void deleteSecSysGrpByIdIdx( ICFSecAuthorization Authorization,
		$implCommaIJavaOptAtomType$ argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecSysGrp cur;
		LinkedList<CFSecBuffSecSysGrp> matchSet = new LinkedList<CFSecBuffSecSysGrp>();
		Iterator<CFSecBuffSecSysGrp> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecSysGrp> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecSysGrp)(schema.getTableSecSysGrp().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSysGrpId() ));
			deleteSecSysGrp( Authorization, cur );
		}
	}

	@Override
	public void deleteSecSysGrpByUNameIdx( ICFSecAuthorization Authorization,
		String argName )
	{
		CFSecBuffSecSysGrpByUNameIdxKey key = (CFSecBuffSecSysGrpByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrp().newByUNameIdxKey();
		key.setRequiredName( argName );
		deleteSecSysGrpByUNameIdx( Authorization, key );
	}

	@Override
	public void deleteSecSysGrpByUNameIdx( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpByUNameIdxKey argKey )
	{
		CFSecBuffSecSysGrp cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecSysGrp> matchSet = new LinkedList<CFSecBuffSecSysGrp>();
		Iterator<CFSecBuffSecSysGrp> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecSysGrp> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecSysGrp)(schema.getTableSecSysGrp().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSysGrpId() ));
			deleteSecSysGrp( Authorization, cur );
		}
	}

	@Override
	public void deleteSecSysGrpBySecLevelIdx( ICFSecAuthorization Authorization,
		ICFSecPubSchema.SecLevelEnum argSecLevel )
	{
		CFSecBuffSecSysGrpBySecLevelIdxKey key = (CFSecBuffSecSysGrpBySecLevelIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrp().newBySecLevelIdxKey();
		key.setRequiredSecLevel( argSecLevel );
		deleteSecSysGrpBySecLevelIdx( Authorization, key );
	}

	@Override
	public void deleteSecSysGrpBySecLevelIdx( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpBySecLevelIdxKey argKey )
	{
		CFSecBuffSecSysGrp cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecSysGrp> matchSet = new LinkedList<CFSecBuffSecSysGrp>();
		Iterator<CFSecBuffSecSysGrp> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecSysGrp> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecSysGrp)(schema.getTableSecSysGrp().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSysGrpId() ));
			deleteSecSysGrp( Authorization, cur );
		}
	}
}
